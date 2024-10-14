import time
from rich.progress import Progress

WAIT_TIME_SECONDS = 0.1 


def log_progress(task_name, total_steps):
    with Progress() as progress:
        task = progress.add_task(task_name, total=total_steps)
        update_progress(progress, task)


def update_progress(progress, task):
    """Refreshes the progress bar."""
    while not progress.finished:
        progress.update(task, advance=1)
        time.sleep(WAIT_TIME_SECONDS)
