Building PyREBox
================

- Installing dependencies

  * For Debian based distributions: 
      
    ``apt-get install build-essential zlib1g-dev pkg-config libglib2.0-dev binutils-dev libboost-all-dev autoconf libtool libssl-dev libpixman-1-dev libpython-dev python-pip virtualenv python-capstone``

  * Required python packages (see the next paragraph for installation instructions):
      
    ``ipython>=5,<6 sphinx sphinx-autobuild prettytable pefile capstone distorm3 pycrypto pytz``

- We strongly recommend to use a virtual env to install your python dependencies. If you have a local installation of volatility, it will intefere with the volatility package used by PyREBox.

  * Create the virtual env:
  
    ``virtualenv pyrebox_venv`` 

  * Once it has been created, activate it in order to install your python dependencies:

    ``source pyrebox_venv/bin/activate``

  * To install the python dependencies you can use pip: 
      
    ``pip install -r requirements.txt``

  * Do not forget to activate your virtual env every time you want to start PyREBox!

    ``source pyrebox_venv/bin/activate``
  
- Project configuration and building

  ``./build.sh``

Installing PyREBox
==================

PyREBox package installation is not yet supported.
