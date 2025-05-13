import multiprocessing

DATADIR = "/opt/skills/dat"
DATABASE = f"{DATADIR}/db"
WORKER_PROCESSES = 1  # multiprocessing.cpu_count() # multiple workers will depend on persisting session data to a DB instead of runtime memory
