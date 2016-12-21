# Variables for VM: elk
elk_box = 'centos/7'
elk_hostname = 'elk'
elk_domain = 'lab.int'
elk_ip_private = '10.10.100.100'
elk_cpus = '1'
elk_ram = '4096'

# Variables for VM: server
server_box = 'centos/7'
server_hostname = 'server'
server_domain = 'lab.int'
server_ip_private = '10.10.100.101'
server_cpus = '1'
server_ram = '512'

#START VAGRANT MULTIPLE MACHINE CONFIG

Vagrant.configure("2") do |config|
  #config.vm.synced_folder ".", "/vagrant", type: "rsync",
  
# START GLOBAL PROVISION SECTION
  config.vm.provision "shell", inline: <<-SHELL
     sudo yum -y update

  SHELL
# FINISH GLOBAL PROVISION SECTION

# ==========================
# Start  Config for VM: elk

	config.vm.define "elk" do |elk|
		
		elk.vm.box = elk_box
	  	elk.vm.hostname = elk_hostname +'.'+ elk_domain
	  	elk.vm.network "private_network", ip: elk_ip_private
  		
		elk.vm.provider "virtualbox" do |elk|
			elk.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
			elk.cpus = elk_cpus
			elk.memory = elk_ram
  		end
    
	    # START elk PROVISION SECTION
	    elk.vm.provision "shell", inline: <<-SHELL
	    	sudo ifup eth1
	    	yum install -y wget unzip epel-release
	    	sudo setsebool -P httpd_can_network_connect 1

	    	################################################ JAVA SECTION ####################################################
	    	echo "-------------------------------------------INSTALL ORACLE JAVA 8.73----------------------------------------"
	    	wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u73-b02/jdk-8u73-linux-x64.rpm"
	    	sudo yum -y localinstall jdk-8u73-linux-x64.rpm
	    	rm -rf /home/vagrant/jdk-8u*-linux-x64.rpm 
	    	echo "-------------------------------------------ORACLE JAVA WAS INSTALLED---------------------------------------"
	    	################################################ JAVA SECTION ####################################################



	    	################################################ ELASTICSEARCH SECTION ###########################################
	    	echo "-------------------------------------------IMPORT ELASITICSEARCH GPG-KEY-----------------------------------"
	    	sudo rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch

	    	echo "-------------------------------------------COPY ELASTICSEARCH REPO FILE------------------------------------"
			sudo cp /vagrant/repo/elasticsearch.repo /etc/yum.repos.d/elasticsearch.repo

			echo "-------------------------------------------INSTALL ELASTICSEARCH-------------------------------------------"
			sudo yum -y install elasticsearch

			echo "-----------------ADD NETWORK.HOST CONFIGURATION TO /ETC/ELASTICSEARCH/ELASTICSEARCH.YML--------------------"
			sudo sed -i '54s/.*/network.host: localhost/' /etc/elasticsearch/elasticsearch.yml

			echo "-------------------------------------------START ELASTICSEARCH---------------------------------------------"
			sudo systemctl start elasticsearch
			echo "-------------------------------------------AUTOSTART ELASTICSEARCH-----------------------------------------"
			sudo systemctl enable elasticsearch
	    	################################################ ELASTICSEARCH SECTION ###########################################



			################################################ KIBANA SECTION ##################################################
			echo "-------------------------------------------COPY KIBANA REPO FILE-------------------------------------------"
			sudo cp /vagrant/repo/kibana.repo /etc/yum.repos.d/kibana.repo

			echo "-------------------------------------------INSTALL KIBANA--------------------------------------------------"
			sudo yum -y install kibana

			echo "----------------------ADD SERVER.HOST CONFIGURATION TO /OPT/KIBANA/CONFIG/KIBANA.YML-----------------------"
			sudo sed -i '5s/.*/server.host: "localhost"/' /opt/kibana/config/kibana.yml

			echo "-------------------------------------------START KIBANA----------------------------------------------------"
			sudo systemctl start kibana
			echo "-------------------------------------------AUTOSTART KIBANA------------------------------------------------"
			sudo systemctl enable kibana.service

			echo "-------------------------------------------Load and Install Kibana Dashboards------------------------------"
			cd ~ && \
			curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip && \
			unzip beats-dashboards-*.zip && \
			cd beats-dashboards-* && \
			./load.sh

			################################################ KIBANA SECTION ##################################################



			################################################ NGINX REVERSE PROXY SECTION #####################################
			echo "------------------------------------------ INSTALL NGINX --------------------------------------------------"
			sudo yum -y install nginx httpd-tools
			
			echo "------------------------------Create user for http-authentication------------------------------------------"
			sudo htpasswd -b -c /etc/nginx/htpasswd.users kibanaadmin Qazxc123

			echo "------------------------------Clear server setting for port 80 in /etc/nginx/nginx.conf--------------------"
			sudo sed -i '37,88d' /etc/nginx/nginx.conf

			echo "------------------------------Copy proxy config for handling Kibana----------------------------------------"
			cp /vagrant/nginx/kibana.conf /etc/nginx/conf.d/kibana.conf

			echo "------------------------------Start NGINX------------------------------------------------------------------"
			sudo systemctl start nginx
			
			echo "------------------------------AUTOSTART NGINX--------------------------------------------------------------"
			sudo systemctl enable nginx
			################################################ NGINX REVERSE PROXY SECTION #####################################



			################################################ LOGSTASH CERTIFICATE SECTION ####################################
			#echo "------------------------INSERT LINE WITH PRIVATE SERVER IP FOR CERTIFICATE GENERATION----------------------"
			#sudo sed -i '227s/.*/subjectAltName = IP: 10.10.100.100/' /etc/pki/tls/openssl.cnf

			#echo "------------------------CERTIFICATE GENERATION-------------------------------------------------------------"
			#cd /etc/pki/tls &&
			#sudo openssl req -config /etc/pki/tls/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash-forwarder.key -out /etc/pki/tls/certs/logstash-forwarder.crt

			sudo cp /vagrant/certs/logstash-forwarder.crt /etc/pki/tls/certs/logstash-forwarder.crt && \
			sudo cp /vagrant/certs/logstash-forwarder.key /etc/pki/tls/private/logstash-forwarder.key && \
			sudo chmod 644 /etc/pki/tls/certs/logstash-forwarder.crt /etc/pki/tls/private/logstash-forwarder.key && \
			sudo chown root:root /etc/pki/tls/certs/logstash-forwarder.crt /etc/pki/tls/private/logstash-forwarder.key

			################################################ LOGSTASH CERTIFICATE SECTION ####################################			

			

			################################################ LOGSTASH SECTION ################################################
			echo "-------------------------------------------COPY LOGSTASH REPO FILE-----------------------------------------"
			sudo cp /vagrant/repo/logstash.repo /etc/yum.repos.d/logstash.repo

			echo "-------------------------------------------INSTALL LOGSTASH------------------------------------------------"
			sudo yum update
			sudo yum -y install logstash

			echo "-------------------------------------------COPY LOGSTASH INPUT---------------------------------------------"
			sudo cp /vagrant/logstash/02-beats-input.conf /etc/logstash/conf.d/02-beats-input.conf


			echo "-------------------------------------------COPY LOGSTASH FILTER--------------------------------------------"
			sudo cp /vagrant/logstash/10-syslog-filter.conf /etc/logstash/conf.d/10-syslog-filter.conf

			echo "-------------------------------------------COPY LOGSTASH OUTPUT--------------------------------------------"
			sudo cp /vagrant/logstash/30-elasticsearch-output.conf /etc/logstash/conf.d/30-elasticsearch-output.conf

			echo "-------------------------------------------CHECK LOGSTASH CONFIGURATION------------------------------------"
			sudo service logstash configtest

			echo "-------------------------------------------RESTART LOGSTASH------------------------------------------------"
			sudo systemctl restart logstash

			echo "-------------------------------------------AUTOSTART LOGSTASH----------------------------------------------"
			sudo chkconfig logstash on
			################################################ LOGSTASH SECTION ################################################		



			################################################ Filebeat PREPARATION SECTION ####################################
			echo "--------------------------Load Filebeat Index Template in Elasticsearch------------------------------------"
			cd ~ && \
			curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json && \
			curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json
			################################################ Filebeat PREPARATION SECTION ####################################

			################################################ Topbeat PREPARATION SECTION #####################################
			cd ~ && \
			curl -O https://raw.githubusercontent.com/elastic/topbeat/master/etc/topbeat.template.json && \
			curl -XPUT 'http://localhost:9200/_template/topbeat' -d@topbeat.template.json
			################################################ Topbeat PREPARATION SECTION #####################################

	    SHELL

    # FINISH elk PROVISION SECTION

  end

# End Config for VM: elk
# ==========================

# ==========================
# Start  Config for VM: server

	config.vm.define "server" do |server|
		
		server.vm.box = server_box
	  	server.vm.hostname = server_hostname +'.'+ server_domain
	  	server.vm.network "private_network", ip: server_ip_private
		
		server.vm.provider "virtualbox" do |server|
			server.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
			server.cpus = server_cpus
			server.memory = server_ram
  		end
    
	    # START server PROVISION SECTION
	    server.vm.provision "shell", inline: <<-SHELL
	        
	        ############################################### BEATS SECTION ####################################################
	        echo "-------------------------------------------Copy Logstash handshake certificate-----------------------------"
	        sudo cp /vagrant/certs/logstash-forwarder.crt /etc/pki/tls/certs
	        
	        echo "-------------------------------------------IMPORT ELASITICSEARCH GPG-KEY-----------------------------------"
			sudo rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch

			echo "-------------------------------------------COPY BEATS REPO----------------------------------------------"
			cp /vagrant/repo/elastic-beats.repo /etc/yum.repos.d/elastic-beats.repo
			############################################### BEATS SECTION ####################################################

			############################################### FILEBEAT SECTION #################################################
			echo "-------------------------------------------INSTALL FILEBEAT------------------------------------------------"
			sudo yum -y install filebeat
			
			echo "-------------------------------------------COPY FILEBEAT CONFIG--------------------------------------------"
			sudo cp /vagrant/filebeat/filebeat.yml-centos /etc/filebeat/filebeat.yml

			echo "-------------------------------------------AUTOSTART FILEBEAT----------------------------------------------"
			sudo systemctl enable filebeat
			echo "-------------------------------------------START FILEBEAT--------------------------------------------------"
			sudo systemctl start filebeat
			############################################### FILEBEAT SECTION #################################################


			############################################### TOPBEAT SECTION ##################################################
			echo "-------------------------------------------INSTALL FILEBEAT------------------------------------------------"
			sudo yum -y install topbeat
			
			echo "-------------------------------------------COPY TOPBEAT CONFIG---------------------------------------------"
			sudo cp /vagrant/topbeat/topbeat.yml /etc/topbeat/topbeat.yml

			echo "-------------------------------------------AUTOSTART TOPBEAT-----------------------------------------------"
			sudo systemctl enable topbeat
			echo "-------------------------------------------START TOPBEAT---------------------------------------------------"
			sudo systemctl start topbeat
			############################################### TOPBEAT SECTION ##################################################

	        

	    SHELL
    	# FINISH server PROVISION SECTION

  	end

# End Config for VM: server
# ==========================

end
# END VAGRANT MULTIPLE MACHINE CONFIG