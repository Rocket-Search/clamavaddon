# clamavaddon
OnAccessScan for ClamAV with fanotify

simple source code based on libclamav and the fanotify systemcall for linux.

operating mode: first scan the file an than decides if the file is blocked (FAN_DENY) or allowed (FAN_ALLOW) .

prerequisites: clamAV (https://www.clamav.net/)

More information:
https://www.man7.org/linux/man-pages/man7/fanotify.7.html
https://www.clamav.net/documents/libclamav

if you have any question, don't hesitate to contact me software.moore@gmail.com
