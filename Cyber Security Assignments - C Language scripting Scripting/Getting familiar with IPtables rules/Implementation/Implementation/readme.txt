Ioannis Markou A.M:2016030126

-domains was made with host and awk. it takes ~7-9 minutes to run with the domains text file that you provided but works like a charm. It gets the ip addresses based on the domains, writes them in IPAddresses file and then creates rules based on these. There is no need to run -domains and then -ips to create the rules. Dig was faster but I could not manage to get the desired outputs.
-sometimes the first run takes a little over 10 minutes but the next runs are like described above.
-ips works if we have readily available ip addresses. Runs way faster since it works directily with ips. It takes input from the file provided.
-The other commands were simple linux commands
-Answer to the question: The ads of some of the websites did get removed. However some of the ads persisted, I imagine because we did not list ALL the possible ad providers, therefore some of the ads went through.
