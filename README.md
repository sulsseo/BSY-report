# BSY bonus task report

This report describes step by step solution of bonus task present in Security Systems course on Czech Technical University.

## ⚡️ First stage

We are receiving a pcap file, unique token, and server information as the entry point to this assignment — the pcap file you can find in this repo. Other provided information is listed below.

- server: `192.168.1.167:9292`
- my token identificator for this task: `HorribleDancer`

First of all, let's check out what we can find on this server just by running `ncat 192.168.1.167 9292` command on my virtual server in BSY network. Getting result:

```text
***************************************************************
Bonus assignment part 1. Not relevant to other assignemnts.
****************************************************************


<Grinch> Please provide your token
HorribleDancer
<Grinch> What is the IP of the C&C?

<Grinch> What is the periodicity of the communication in seconds? (Remove decimals, for example 122.7 becomes 122)

<Grinch> How many times did the victim computer connect to the C&C IP?

<Grinch> Was any malicious executable downloaded (Yes/No)?

```

So now I have a bunch of question which can be answered after pcap analysis.

### pcap analysis

From the obtained questions, we can estimate that the pcap file is capturing some kind of attack. We know this attack may use Command and Control botnet, and we can detect this by some periodically repeated action. When we open the capture file in most popular capture analysis software [Wireshark](https://www.wireshark.org/), it's clear that it has precisely 10000 records and 2:07 hours duration. 

![img01](img/img01.png)

```text
<Grinch> Please provide your token
Horrible  Dancer
<Grinch> What is the IP of the C&C?
ff02::c
<Grinch> What is the periodicity of the communication in seconds? (Remove decimals, for example 122.7 becomes 122)
1
<Grinch> How many times did the victim computer connect to the C&C IP?
11
<Grinch> Was any malicious executable downloaded (Yes/No)?
No
You answered correctly 1 out of 4 questions.
```

TODO

```text
TODO
```

```text
<Grinch> Please provide your token
HorribleDancer
<Grinch> What is the IP of the C&C?
37.48.125.108
<Grinch> What is the periodicity of the communication in seconds? (Remove decimals, for example 122.7 becomes 122)
300
<Grinch> How many times did the victim computer connect to the C&C IP?
2
<Grinch> Was any malicious executable downloaded (Yes/No)?
No
<Grinch> Saving you, is that what you think I was doing? Wrong-o. I merely noticed that you're improperly packaged, my dear.
<Grinch> Here is something you migt need later: 3232235903
Knock knock... Your VM might be handy.
Hint: MzcgMzAgMzAgMzAgMmMgMzggMzAgMzAgMzAgMmMgMzkgMzAgMzAgMzAgMmMgMzEgMzAgMzAgMzAgMzA=
<Grinch> This is the end of stage 1. You rock!
```

## Second stage

Okay great. The first stage ends with the message includes some hints and ciphers. We now have some number that looks kind of random, but it definitely hides some piece of information. One of the first things I personally do if I don't know I use Google search. Let's try to find `3232235903` on Google and see.

![ip](img/ip.gif)

Yes. The answer is in the third position; the number `3232235903` is a decimal representation of IPv4 address `192.168.1.127` probably internal address of our next target machine. What to do next? We still have hint laying there asking for attention. If we focus on `MzcgMzAgMzAgMzAgMmMgMzggMzAgMzAgMzAgMmMgMzkgMzAgMzAgMzAgMmMgMzEgMzAgMzAgMzAgMzA=` string, we can see it's a continuous sequence of characters that end with an equal sign. From previous experiences with encoding, I know that Base64 has a similar output pattern. Let's decode this string.

```bash
print "MzcgMzAgMzAgMzAgMmMgMzggMzAgMzAgMzAgMmMgMzkgMzAgMzAgMzAgMmMgMzEgMzAgMzAgMzAgMzA=" | base64 -d
```

The output is:

```bash
37 30 30 30 2c 38 30 30 30 2c 39 30 30 30 2c 31 30 30 30 30
```

So now we have a pair of numbers combined with the characters `c`. It's still somehow encoded information; in this case, it seems like hex. Let's add some pipe and look for what we can get.

```bash
$ print "MzcgMzAgMzAgMzAgMmMgMzggMzAgMzAgMzAgMmMgMzkgMzAgMzAgMzAgMmMgMzEgMzAgMzAgMzAgMzA=" | base64 -d | xxd -r -p
> 7000,8000,9000,10000
```

Group of some numbers? Maybe ports for a previously found machine? That's a lot of information. We can try to scan given machine and see if some of these ports is not open. For this purpose, I use a fast Nmap scan to just look around. It is easy to detect this kind of scan, but in this task, it does not matter.

```bash
nmap -sS -n -v 192.168.1.127 -p- -T5 --min-parallelism 200 --max-rtt-timeout 5 --max-retries 1 --max-scan-delay 0 --min-rate 1000

Host is up (0.00031s latency).
Not shown: 65531 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
902/tcp  open  iss-realsecure
6667/tcp open  irc
8081/tcp open  blackice-icecap
MAC Address: 08:00:27:06:8F:03 (Oracle VirtualBox virtual NIC)
```

So we have some ports opened, but none of these ports are exact numbers `7000, 8000, 9000` or `10000`. Port `22` is a provider of ssh. In this case, it is just remote access to manage the machine. The closest to our hint is the port `8081`, providing some weird service.

```bash
$ curl 192.168.1.127:8081
```

A quick look for what this service is. And it looks like a website hosting.  

```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href="www.asdf.com/">www.asdf.com/</a></li>
</ul>
<hr>
</body>
</html>
```

After a more in-depth analysis of this website, here is nothing unusual. Compare to the original `www.asdf.com` website accessible from the public internet, this clone is more or less the same as the original site. Let's continue with the port analysis.

We have a remaining ports `902` and `6667`. On port `902` is another ssh-agent. Not interesting for us. After accessing the last port, we are getting short ASCII animation. Which unfortunately hides no new information on our treasure path.

```text
                  .........    @@@@@    @@@@@        ..........
                  .........   @     @  @     @       ..........
                  ........       @@@   @     @        .........
                  .......      @@      @     @         .......
                  ......      @@@@@@@   @@@@@  th       ......
                  .....     -----------------------      .....
                  ....        C  E  N  T  U  R  Y         ....
                  ...       -----------------------        ..
                  ..        @@@@@ @@@@@ @   @ @@@@@        ..
                  ==          @   @      @ @    @          ==
                __||__        @   @@@@    @     @        __||__
               |      |       @   @      @ @    @       |      |
      _________|______|_____  @   @@@@@ @   @   @  _____|______|_________


< o                                                                            >
```

Uhhh. No ports are remaining, and we still have no hint of what to do. Let's go back to hint from previous stage. Try to deeper analyze the text.
