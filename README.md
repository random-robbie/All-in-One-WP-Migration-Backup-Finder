# All-in-One-WP-Migration-Backup-Finder


Based off the work from https://vavkamil.cz/2020/03/25/all-in-one-wp-migration/

This will smash the fuck outta the server to give up a backup it's not a 100% affective way but does a job.

It will send around 3024000 requests so be prepared to get abused by the system admin for generating loads of 404 logs or it causing the log system to be hammered.

It will not test the non vul versions and it will tell you to check a link if the backups are exposed any way.


`finder.py` requires `WFUZZ` to be installed and on your path.

`ffufinder.py` requires `ffuf` to be installed and on your path.

How to run
---

finder.py:
```
python3 finder.py -u https://somewordpresswebsite.com [-d 10]
```
ffufinder.py:
```
python3 ffufinder.py -u https://somewordpresswebsite.com [-d 10]
```

or

```
docker run --rm txt3rob/all-in-one-wp-migration-backup-finder https://www.website.com
```
![screenshots](https://github.com/random-robbie/All-in-One-WP-Migration-Backup-Finder/raw/master/finder.png)
