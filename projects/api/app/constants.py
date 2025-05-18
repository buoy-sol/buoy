import multiprocessing

DATADIR = "/opt/skills/dat"
DATABASE = f"{DATADIR}/db"

# for every fee the card creator has to pay upfront
RENT_UPFRONT_COSTS_LAMPORTS = 6 * 5_000

WORKER_PROCESSES = 1  # multiprocessing.cpu_count() # multiple workers will depend on persisting session data to a DB instead of runtime memory
