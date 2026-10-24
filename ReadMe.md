# SSL Checker

A command line tool to check SSL certificates.  

## Description

This command line tool allows to check SSL certificates of servers available 
in the Internet network.

Functionality supported by the tool is listed below:
- Storing built-in root certificate files;
- Automatic verification of built-in root certificate files via the source URL;
- Selection of root certificates pool, including the system one and custom pools;
- Retrieval of SSL certificates provided by web servers by their domain name and port number;
- Verification of SSL certificates provided by web servers using the selected pool of root certificates;
- Automatic retrieval, caching and checks of certificate revocation lists (CRLs);  
- Automatic check of revocation status of certificates using a custom certificate pool;
- Eye-friendly coloured textual user interface supporting ANSI colours.

## Installation
`go install github.com/vault-thirteen/SSL-Checker/cmd/tool/checker@latest`

## Usage Example
`checker.exe "settings\app1.json"`


## Detailed Description

For those of you who know nothing or want to know more, this detailed 
description is provided here.

First of all, this tool is quite simple, but robust and powerful. It can store 
several separated pools of root certificates to emulate separate working 
environments. This tool comes with a small set of pools already bundled into the 
tool as an example. You can add your own custom certificates if you want. 

Each custom root certificate pool must be registered in its own settings file 
and a list of all pools must be registered in the application configuration 
file. See the sample configuration files for more information.

The tool can switch on-fly between loaded root certificate pools with zero 
effort needed from the end user. When you switch between the pools, do 
remember one thing – pools are selected by their zero-based index, not by the 
number, i.e. the first custom pool is using index 0. Negative indices mean 
switching to a root certificate pool provided by the operating system.

To enforce and raise level of security, all the bundled pools of custom root 
certificates are checked and verified at the program's start-up. This 
procedure may take some time, but is performed only once per program start. 

The main purpose of this tool is to check validity of SSL certificates provided 
by web servers in the Internet network. To check someone's certificate, a user 
specifies a domain name, e.g. `example.org` and a port number, e.g. `443` of 
the web server to check. If port number is omitted, the default one is selected, 
which is the default _HTTPS_ port number 443. 

In the first stage of the process of certificate check, the tool connects to 
the specified web server, retrieves its certificates, verifies them against the 
root certificates of the selected pool, and prints some important details about 
received certificates. 

In the second stage, the tool performs revocation checks of the received 
certificates. Certificate revocation lists (or simply, CRLs) are automatically 
retrieved, cached for future usage and checked using the working pool of root 
CA certificates.

It is important to note that CRL lists are stored separately for each individual 
certificate pool. This means that if you, for example, select the system pool 
and check a certificate, its CRL lists will be cached together with the system 
pool. If you switch to a custom pool, it will use its own separate CRL lists. 
Such mechanics allows separation of working environments to increase the level 
of security.

CRL lists are not only cached on disk storage to avoid downloading again and 
again, but also have a validity time. This means that cached CRL files are 
re-downloaded from time to time in order to keep them in a fresh state. All 
this is done automatically without user interaction.

If any critical error occurs during the process of check, the tool shows it and 
stops processing the certificates. If all the certificates and associated CRLs 
are successfully downloaded, the results of certificate verification and 
revocation checks are shown on screen. Each verification error per each SSL 
certificate will be shown if present.

If everything is good with retrieved certificates, you will see two green 
messages: one about no errors in certificates, and one about the fact that all 
the certificates are actual, i.e. not revoked by the issuer.  

Be aware, that in order to get valid results, your operating system and this 
tool must be updated to the latest version possible. This means that updates 
for your O.S. must be enabled, all the latest patches installed and this tool 
must be compiled with the latest language compiler version available. If you 
compile this tool with an outdated `Go` language version, this tool will not 
show valid results. 

## Supported Operating Systems

Due to the limitations of `Go` programming language, which does not allow to 
list system root certificates, at the moment, only _Windows_ operating systems 
are supported. The tool was successfully tested on a `Windows 10 22H2` O.S. 
with all the latest ESU updates installed.

Support for other operating systems may arrive somewhere in the future.

## Feedback

In the conclusion, it is important to note that this tool is very simple, but
it does its work well. However, if you happen to find any bugs in this product 
and want to provide feedback, you are welcome into this _GitHub_ repository.

Have a good day and stay safe.
