# -------------------------------------------------------------------------------
#
#   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group
#
#   PyREBox: Python scriptable Reverse Engineering Sandbox
#   Author: Jonas Zaddach
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#   MA 02110-1301, USA.
#
# -------------------------------------------------------------------------------

FROM ubuntu:18.04
MAINTAINER Jonas Zaddach

ENV PREFIX /home
RUN apt-get update
RUN apt-get install -y python3 python3-pip
RUN export python=python3
#Install packages
RUN apt-get install -y --fix-missing build-essential zlib1g-dev pkg-config \
                       libglib2.0-dev binutils-dev libboost-all-dev \
                       autoconf libtool libssl-dev libpixman-1-dev \
                       libpython-dev python-pip \
                       git curl vim

#upgrade pip
RUN python3 -m pip install --upgrade pip


#clone pybox
RUN git clone https://github.com/Cisco-Talos/pyrebox pyrebox
WORKDIR pyrebox
RUN python3 -m pip install -r requirements.txt
RUN ./build.sh
# i don't know why pyrebox-i386 uses python2 still 
RUN python2 -m pip install distorm3 ipython capstone
#RUN cp /usr/local/lib/python2.7/dist-packages/capstone/lib/libcapstone.so /usr/local/lib
#RUN cp /usr/local/lib/python3.6/dist-packages/capstone/lib/libcapstone.so /usr/local/lib
RUN ldconfig

#OPTIONAL: Copy VM in. Left as an example

#RUN mkdir /images
#ADD files/template_pybox_vm_winxp.tar.gz /images
#RUN echo "./start_i386.sh /images/xpsp3.qcow2" > ~/.bash_history

EXPOSE 5900
ENTRYPOINT ["/bin/bash"]
