import logging


logging.basicConfig(
    format='[ %(asctime)s ] [ %(levelname).4s ] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.DEBUG)


def info(message: str) -> None:
    logger = logging.getLogger()
    logger.info(message)


def warning(message: str) -> None:
    logger = logging.getLogger()
    logger.warning(message)


def error(message: str) -> None:
    logger = logging.getLogger()
    logger.error(message)


def critical(message: str) -> None:
    logger = logging.getLogger()
    logger.critical(message)
