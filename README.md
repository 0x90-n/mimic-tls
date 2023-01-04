# mimic-tls

cat domains | ./mimic -stdin -localAddr "your_local_ip" > results
Note: If one line in "domains" file is an IP address, golang will remove the Server Name extension from the client hello sent to that IP

cat results | python3 table.py
# Copy paste into table.tex
pdflatex table.tex

# evince table.pdf

