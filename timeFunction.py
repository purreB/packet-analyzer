import time


def printable_timestamp(ts, resol):
    ts_sec = ts // resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    return '{}.{}'.format(ts_sec_str, ts % resol)