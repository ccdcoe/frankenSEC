# frankenSEC

## SEC rules for Crossed Swords 2019 (XS19) logs and alerts
This repository contains SEC event correlation rules used in XS19 yellow team data processing as a part of our overarching [frankenstack](https://github.com/ccdcoe/frankenstack) project.
As the name may suggest, the contents are a Frankenstein monster of packaged SEC rules originally developed during several iterations of the [frankencoding event](https://github.com/ccdcoe/Frankencoding) since XS17. Much inspiration has been drawn from [SagittariuSEC](https://github.com/markuskont/SagittariuSEC), a master thesis outlining a package of SEC rules.

## Basic operation
 * These rules expect that the events have been enriched by 'peek' (https://github.com/ccdcoe/go-peek).
 * In our environment setup, enriched events are consumed from Kafka by the simple-kafka-consumer (a python script that is a part of the overarching [Frankenstack repo](https://github.com/ccdcoe/frankenstack)) and its output is directed to a named pipe (fifo). SEC opens the named pipe with (--input) and processes incoming events.
  * However, the rules are input source agnostic, so it does not matter how you feed SEC the input events.
 * SEC rules are responsible for initial parsing, filtering, correlation and in many cases adds meaning to the events.
 * SEC writes relevant events (again) to a separate named pipe (fifo). These are read by a tool sec2alerta (bundled with this repo) we developed specifically for this purpose.
 * The tool sec2alerta makes sure the event has all the required fields for sending events to the [Alerta](https://alerta.io/) Server API. 
  * NB! Note the alerta [de-duplication](https://docs.alerta.io/en/latest/server.html#de-duplication) and [correlation](https://docs.alerta.io/en/latest/server.html#simple-correlation) functionality. The rules are constructed in a way that sequences of events/alerts/attacks taking place between the same pair of hosts are correlated together under a single 'umbrella' event. The information from the latest event is prominent, but clicking on the alert reveals the previous (historical) events that have been correlated together.
 * Events are visualized for the XS training audience (RT) on the [Alerta Dashboard](https://github.com/alerta/alerta). However, same information could be accessed on the command line using the alerta client.

## Versions
You need to run SEC version 2.8.1 or newer to make use of some of the `lcall` actions used in the rules.

## Running the stuff
Mind the various directories and paths that are expected here. This only serves as an example.

```
# Run SEC as a deamon
/opt/sec/bin/sec --conf=/opt/sec/rules/*.sec --input=/opt/sec/inputs/fifo --intevents --intcontexts --reopen-timeout=60 --dumpfts --rwfifo --keepopen --log=/opt/sec/var/sec.log --detach

# Run simple-kafka-consumer
/opt/frankenstack/scripts/simple-kafka-consumer.py --kafka-meta --brokers <ip-redacted> --consume-topics peek-topic1 peek-topic2 | tee /opt/sec/inputs/generic

# Run sec2alerta
/opt/sec2alerta/sec2alerta.py --fifo /opt/sec/outputpipe
```


## Links
SEC - https://simple-evcorr.github.io/
peek - https://github.com/ccdcoe/go-peek
simple-kafka-consumer - https://github.com/ccdcoe/frankenstack (/scripts)
sec2alerta - https://github.com/ccdcoe/frankenSEC (/sec2alerta)
alerta - https://alerta.io/ & https://github.com/alerta/alerta & https://github.com/markuskont/dockerfiles (/alerta)
