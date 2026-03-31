FROM freeradius/freeradius-server:latest
COPY raddb/ /etc/raddb/
CMD ["radiusd", "-f", "-l", "stdout", "-X"]
