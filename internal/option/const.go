package option

const (
	version = "1.0"
	author  = "m1tz"
	banner  = `
  ·▄▄▄▄   ▐ ▄ .▄▄ ·▄▄▄▄▄ ▄▄▄· ▄ •▄ ▄▄▄ .
  ██▪ ██ •█▌▐█▐█ ▀.•██  ▐█ ▀█ █▌▄▌▪▀▄.▀·
  ▐█· ▐█▌▐█▐▐▌▄▀▀▀█▄▐█.▪▄█▀▀█ ▐▀▀▄·▐▀▀▪▄ 2
  ██. ██ ██▐█▌▐█▄▪▐█▐█▌·▐█ ▪▐▌▐█.█▌▐█▄▄▌
  ▀▀▀▀▀• ▀▀ █▪ ▀▀▀▀ ▀▀▀  ▀  ▀ ·▀  ▀ ▀▀▀

        (c) ` + author + ` — v` + version
	usage = `
  [stdin] | dnstake [options]
  dnstake -t HOSTNAME [options]`
	options = `
  -t, --target <HOST/FILE>    Define single target host/list to check
  -c, --concurrent <i>        Set the concurrency level (default: 25)
  -s, --silent                Suppress errors and/or clean output
  -o, --output <FILE>         Save vulnerable hosts to FILE
  -g, --gandiapikey <APIKEY>  Gandi API Key to check existence of base domain - important
  -h, --help                  Display its help`
	examples = `
  dnstake -t (sub.)domain.tld
  dnstake -t hosts.txt
  dnstake -t hosts.txt -o ./dnstake.out
  dnstake -t hosts.txt -g gandiapikey -o ./dnstake.out
  cat hosts.txt | dnstake
  subfinder -silent -d domain.tld | dnstake
  `
)
