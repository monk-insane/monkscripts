# /bin/bash

# InstallYara.bash - automates installation of yara on endpoints - written for https://socfortress.medium.com/detect-malcious-file-uploads-with-wazuh-and-yara-88d671b2df08
# Copyright (C) 2024 monkinsane
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

## Script  to install YARA on client

# Install required tools

apt-get install automake jq libtool libssl-dev make gcc pkg-config git libjansson-dev libmagic-dev -y

sleep 5

# Prepare directories

mkdir /usr/share/yara
cd /usr/share/yara

# Get Latest Installation files


LOCATION=$(curl -s https://api.github.com/repos/VirusTotal/yara/releases/latest | grep "tag_name" | awk '{print "https://github.com/VirusTotal/yara/archive/" substr($2, 2, length($2)-3) ".tar.gz"}') 
curl -L -o yara.tar.gz $LOCATION

# Extract & Build

tar xvf yara.tar.gz --directory /usr/share/yara/
YARASRC=$(find -type d -iname "yara*" | head -n 1)
cd $YARASRC
./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet --with-crypto
make
make install

# Download Rules

cd /usr/local
git clone https://github.com/Neo23x0/signature-base.git

# Remove rules that require specific software processors

rm /usr/local/signature-base/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar
rm /usr/local/signature-base/yara/gen_fake_amsi_dll.yar
rm /usr/local/signature-base/yara/gen_vcruntime140_dll_sideloading.yar
rm /usr/local/signature-base/yara/gen_mal_3cx_compromise_mar23.yar
rm /usr/local/signature-base/yara/yara-rules_vuln_drivers_strict_renamed.yar

# Create Rule Compile Script

SCRIPTOUT="/usr/share/yara/yara_update_rules.sh"

echo '#!/bin/bash' | tee $SCRIPTOUT 
echo '# Yara rules - Compiled file creation' | tee -a $SCRIPTOUT 
echo '# Copyright (C) SOCFortress, LLP.' | tee -a $SCRIPTOUT 
echo '#' | tee -a $SCRIPTOUT 
echo '# This program is free software; you can redistribute it' | tee -a $SCRIPTOUT 
echo '# and/or modify it under the terms of the GNU General Public' | tee -a $SCRIPTOUT 
echo '# License (version 2) as published by the FSF - Free Software' | tee -a $SCRIPTOUT 
echo '# Foundation.' | tee -a $SCRIPTOUT 
echo ' ' | tee -a $SCRIPTOUT 
echo '#' | tee -a $SCRIPTOUT 
echo '#------------------------- Aadjust IFS to read files -------------------------#' | tee -a $SCRIPTOUT 
echo 'SAVEIFS=$IFS' | tee -a $SCRIPTOUT 
echo 'IFS=$(echo -en "\n\b")' | tee -a $SCRIPTOUT 
echo '# Static active response parameters' | tee -a $SCRIPTOUT 
echo 'LOCAL=`dirname $0`' | tee -a $SCRIPTOUT 
echo '#------------------------- Folder where Yara rules (files) will be placed -------------------------#' | tee -a $SCRIPTOUT 
echo 'git_repo_folder="/usr/local/signature-base"' | tee -a $SCRIPTOUT 
echo 'yara_file_extenstions=( ".yar" )' | tee -a $SCRIPTOUT 
echo 'yara_rules_list="/usr/local/signature-base/yara_rules_list.yar"' | tee -a $SCRIPTOUT 
echo ' ' | tee -a $SCRIPTOUT 
echo '#------------------------- Main workflow --------------------------#' | tee -a $SCRIPTOUT 
echo ' ' | tee -a $SCRIPTOUT 
echo '# Update Github Repo' | tee -a $SCRIPTOUT 
echo 'cd $git_repo_folder' | tee -a $SCRIPTOUT 
echo 'git pull https://github.com/Neo23x0/signature-base.git' | tee -a $SCRIPTOUT 
echo ' ' | tee -a $SCRIPTOUT 
echo '# Remove .yar files not compatible with standard Yara package' | tee -a $SCRIPTOUT 
echo 'rm $git_repo_folder/yara/generic_anomalies.yar $git_repo_folder/yara/general_cloaking.yar $git_repo_folder/yara/thor_inverse_matches.yar $git_repo_folder/yara/yara_mixed_ext_vars.yar $git_repo_folder/yara/apt_cobaltstrike.yar $git_repo_folder/yara/apt_tetris.yar $git_repo_folder/yara/gen_susp_js_obfuscatorio.yar $git_repo_folder/yara/configured_vulns_ext_vars.yar $git_repo_folder/yara/gen_webshells_ext_vars.yar' | tee -a $SCRIPTOUT 
echo ' ' | tee -a $SCRIPTOUT 
echo '# Create File with rules to be compiled' | tee -a $SCRIPTOUT 
echo 'if [ ! -f $yara_rules_list ]' | tee -a $SCRIPTOUT 
echo 'then' | tee -a $SCRIPTOUT 
echo '    /usr/bin/touch $yara_rules_list' | tee -a $SCRIPTOUT 
echo 'else rm $yara_rules_list' | tee -a $SCRIPTOUT 
echo 'fi' | tee -a $SCRIPTOUT 
echo 'for e in "${yara_file_extenstions[@]}"' | tee -a $SCRIPTOUT 
echo 'do' | tee -a $SCRIPTOUT 
echo '  for f1 in $( find $git_repo_folder/yara -type f | grep -F $e ); do' | tee -a $SCRIPTOUT 
echo '    echo "include \"""$f1"\""" >> $yara_rules_list' | tee -a $SCRIPTOUT 
echo '  done' | tee -a $SCRIPTOUT 
echo 'done' | tee -a $SCRIPTOUT 
echo '# Compile Yara Rules' | tee -a $SCRIPTOUT 
echo '/usr/local/bin/yarac $yara_rules_list /usr/local/signature-base/yara_base_ruleset_compiled.yar' | tee -a $SCRIPTOUT 
echo 'IFS=$SAVEIFS' | tee -a $SCRIPTOUT 
echo 'exit 1;' | tee -a $SCRIPTOUT 

chmod +x $SCRIPTOUT

# Update YARA Rules

bash -x $SCRIPTOUT

exit 0