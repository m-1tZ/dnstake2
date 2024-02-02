package option

const (
	version = "1.0"
	author  = "pwnesia + m1tz"
	banner  = `
  ·▄▄▄▄   ▐ ▄ .▄▄ ·▄▄▄▄▄ ▄▄▄· ▄ •▄ ▄▄▄ .
  ██▪ ██ •█▌▐█▐█ ▀.•██  ▐█ ▀█ █▌▄▌▪▀▄.▀·
  ▐█· ▐█▌▐█▐▐▌▄▀▀▀█▄▐█.▪▄█▀▀█ ▐▀▀▄·▐▀▀▪▄ 2
  ██. ██ ██▐█▌▐█▄▪▐█▐█▌·▐█ ▪▐▌▐█.█▌▐█▄▄▌
  ▀▀▀▀▀• ▀▀ █▪ ▀▀▀▀ ▀▀▀  ▀  ▀ ·▀  ▀ ▀▀▀

        (c) ` + author + ` — v` + version
	usage = `
  [stdin] | dnstake2 [options]
  dnstake2 -t HOSTNAME [options]`
	options = `
  -t, --target <HOST/FILE>    Define single target host/list to check
  -c, --concurrent <i>        Set the concurrency level (default: 25)
  -s, --silent                Suppress errors and/or clean output
  -o, --output <FILE>         Save vulnerable hosts to FILE
  -g, --gandiapikey <APIKEY>  Gandi API Key to check existence of base domain - important
  -h, --help                  Display its help`
	examples = `
  dnstake2 -t (sub.)domain.tld
  dnstake2 -t hosts.txt
  dnstake2 -t hosts.txt -o ./dnstake2.out
  dnstake2 -t hosts.txt -g gandiapikey -o ./dnstake2.out
  cat hosts.txt | dnstake2
  subfinder -silent -d domain.tld | dnstake2
  `
)
