import logging

def get_loggging(name):
    logger = logging.getLogger(name)
     if not logger.handlers:
        loggin.basicConfig(
            level = logging.INFO,
            format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
    return logger