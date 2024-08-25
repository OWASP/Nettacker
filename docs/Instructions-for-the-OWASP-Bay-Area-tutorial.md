0. _**In the beginning, there was … GIT**_:
Clone the latest revision of Nettacker

`> git clone https://github.com/zdresearch/OWASP-Nettacker.git && cd OWASP-Nettacker && pip install -r requirements.txt`

Make sure it works - in the command line, go to the root folder of Nettacker and run the following:

`> python nettacker.py -h`

1. _**Let there be targets:**_
For the purposes of this tutorial, we have created a shooting range somewhere in the realm of z3r0d4y.com . Let's see what subdomains are available there:

`> python nettacker.py -i z3r0d4y.com -m subdomain_scan`

What sorcery is this? To see behind the curtains:

`> python nettacker.py -i z3r0d4y.com -m subdomain_scan -v 5`

OK, but which of these is smells fishier than others? Let's run a quick port scan:

`python nettacker.py -i z3r0d4y.com -m port_scan`

2. _**For thou shalt p4wn**_: Hmm... that "tg1" fellow smells funny. Let's see what its port 80 has to say:

`open tg1.z3r0d4y.com in browser`

A login page - we shall knock on its door soon. But now: Shall we see if we can bruteforce our way into its SSH service?

`> python nettacker.py -i tg1.z3r0d4y.com -m ssh_brute -T 10 -v 5`

Cool. Now, comrades, let us go back to the gates of the login page on port 80...

Shall we write our own fuzzer to brute force our way into this login page? Why not... https://drive.google.com/open?id=1aFgKrdzhV6jb9HDi7LvrM9fjCd8n_hly

Now that we are in, let's see what else is lurking in these dark corners. Notice the URL. Shall we fuzz and see if exploration in the numerical realm gets us anywhere? Why not... https://drive.google.com/open?id=1bG01UT5_VApHFLLf3FD8VV1o_lu_pRC1

Ok, we now have the IP address of an internal docker and access to the WebUI of Nettacker installed there. Let's play.

