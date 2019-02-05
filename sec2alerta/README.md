#sec2alerta
Helper to post SEC events to Alerta (filling in required keywords)

Reads alerta configuration from a config file (example provided)

## Create a named pipe or FIFO beforehand:
```
mkfifo /tmp/myfifo
```

## Run with:
```
./sec2alerta.py -f /tmp/myfifo
```

