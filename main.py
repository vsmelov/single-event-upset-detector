import random
import typing
import logging
import contextlib
import time
import psutil
import bitarray
import bitarray.util
import json

logger = logging.getLogger(__name__)


def init_logging():
    _format = "%(asctime)s %(levelname)s %(name)s %(pathname)s:%(lineno)d %(message)s"
    formatter = logging.Formatter(_format)
    filename = 'detector.log'
    filemode = 'a'

    logger.setLevel(logging.DEBUG)

    # set up logging to console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)

    # set up logging to console
    fh = logging.FileHandler(filename, filemode)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    # add the handler to the root logger
    logger.addHandler(console)
    logger.addHandler(fh)


def get_free_memory():
    return psutil.virtual_memory().free


@contextlib.contextmanager
def measure(name):
    start = time.time()
    try:
        yield
    finally:
        end = time.time()
        ms = round((end-start) * 1000, 3)
        logger.debug(f'{name} in {ms}ms')


class TStat(typing.TypedDict):
    bitSeconds: float
    GbitHours: float
    SEUCases: int
    runSeconds: float
    runHours: float


NO_UPDATE = 0
UPDATE_NO_CHECK = 1
UPDATE_WITH_CHECK = 2


class SEUDetector:
    FREE_MEMORY_USAGE_RATE = 0.75
    CHECK_MEMORY_EVERY = 1
    CHECK_DATA_EVERY = 10
    STATISTICS_FILENAME = 'stat.json'
    MIN_INCREASE_DELAY = 60
    RELATIVE_DATA_LENGTH_CHANGE_TO_UPDATE = 0.2

    def __init__(self):
        self.data = bitarray.bitarray()
        self.force_reinit = False

    def get_memory_to_use(self):
        """ we do not want to use all memory but some small part """
        free = get_free_memory()
        used = len(self.data) / 8
        total = free + used
        to_use = int(total * self.FREE_MEMORY_USAGE_RATE)
        logger.debug(f'{free=} {used=} {total=} {to_use=}')
        return to_use

    def should_update_array(self, use_bits):
        if self.force_reinit:
            logger.debug(f'force_reinit')
            self.force_reinit = False
            return UPDATE_NO_CHECK
        if use_bits != 0 and len(self.data) == 0:
            return UPDATE_NO_CHECK
        if use_bits == 0 and len(self.data) != 0:
            return UPDATE_NO_CHECK
        if use_bits == 0 and len(self.data) == 0:
            return NO_UPDATE
        delta = use_bits - len(self.data)
        rel = abs(delta) / min(use_bits, len(self.data))
        if rel > self.RELATIVE_DATA_LENGTH_CHANGE_TO_UPDATE:
            logger.debug(f'{delta=} {rel=}')
            if delta > 0:
                return UPDATE_WITH_CHECK
            else:
                return UPDATE_NO_CHECK
        return NO_UPDATE

    def load_statistics(self) -> TStat:
        try:
            with open(self.STATISTICS_FILENAME) as f:
                return json.load(f)
        except FileNotFoundError:
            return TStat(
                bitSeconds=0,
                GbitHours=0,
                SEUCases=0,
                runSeconds=0,
                runHours=0,
            )

    def dump_statistics(self, stat: TStat):
        with open(self.STATISTICS_FILENAME, 'w') as f:
            json.dump(stat, f, indent=True)

    def run(self):
        stat = self.load_statistics()
        self.update_array(self.get_memory_to_use() * 8)
        while True:
            self.run_once(stat)

    def run_once(self, stat):
        start_at = time.time()
        last_check_mem = start_at
        last_check_data = start_at

        while True:
            sleep_for = min(self.CHECK_MEMORY_EVERY-(time.time()-last_check_mem),
                            self.CHECK_DATA_EVERY-(time.time()-last_check_data))
            time.sleep(sleep_for)

            if time.time() - last_check_mem >= self.CHECK_MEMORY_EVERY:
                use_bytes = self.get_memory_to_use()
                use_bits = use_bytes * 8
                should = self.should_update_array(use_bits)
                if should == UPDATE_NO_CHECK:
                    self.update_array(use_bits)
                    return
                elif should == UPDATE_WITH_CHECK:
                    self.check_data(stat, start_at)
                    self.update_array(use_bits)
                    return
                elif should == NO_UPDATE:
                    logger.debug(f'update no need')
                    last_check_mem = time.time()
                else:
                    raise ValueError(should)

            if time.time() - last_check_data >= self.CHECK_DATA_EVERY:
                self.check_data(stat, start_at)
                return

    def update_array(self, use_bits):
        use_gbytes = round(use_bits / 8 / 10**9, 3)
        logger.info(f'update data from {len(self.data)} to {use_bits} bits / {use_gbytes} GBytes')

        with measure("clear"):
            del self.data

        with measure("memalloc"):
            self.data = bitarray.bitarray(use_bits)

        with measure('setall ZERO'):
            self.data.setall(0)

    # def random_mess(self):
    #     if random.random() < 0.5:  # simulation
    #         change_index = random.randrange(len(self.data))
    #         logger.info(f'{change_index=}')
    #         self.data[change_index] = 1

    def check_data(self, stat, start_at):
        logger.debug(f'check_data')
        period = time.time() - start_at
        stat['bitSeconds'] += len(self.data) * period
        stat['GbitHours'] = stat['bitSeconds'] / 3600 / 10**9
        stat['runSeconds'] += period
        stat['runHours'] = stat['runSeconds'] / 3600

        one = bitarray.bitarray(1)
        one.setall(1)

        try:
            with measure("search for ONE"):
                index = self.data.index(one)
        except ValueError:
            logger.debug(f'ONE not found')
        else:
            logger.warning(f'ONE was found at {index=}')
            stat['SEUCases'] += 1
            self.force_reinit = True

        self.dump_statistics(stat)


if __name__ == '__main__':
    init_logging()
    logger.info(f'START')
    try:
        detector = SEUDetector()
        detector.run()
    except KeyboardInterrupt:
        logger.info(f'GRACEFUL EXITING')
    except Exception as exc:
        logger.exception(f'unhandled exception {type(exc)}')
    finally:
        logger.info(f'FINISH')
