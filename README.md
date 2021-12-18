# Minecraft Log4j Honeypot

This honeypots runs fake Minecraft server (1.7.2 - 1.16.5 without snapshots) waiting to be exploited. Payload classes are saved to `payloads/` directory. Then it _might_ hellpot them after collection. Not sure, this hasn't been tested. See commit(s).

## Requirements
- Golang 1.16+

## Running

### Natively
```
git clone https://github.com/Adikso/minecraft-log4j-honeypot.git
cd minecraft-log4j-honeypot
go build .
./minecraft-log4j-honeypot
```
