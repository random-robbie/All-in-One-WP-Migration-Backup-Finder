FROM python:3.5-stretch
WORKDIR /root/
RUN git clone https://github.com/random-robbie/All-in-One-WP-Migration-Backup-Finder
WORKDIR /root/All-in-One-WP-Migration-Backup-Finder/
RUN python -m pip install -r requirements.txt
ENTRYPOINT ["python","finder.py","-u"]
