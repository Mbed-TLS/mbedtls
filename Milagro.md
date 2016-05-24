<h2>README for mbed TLS with MILAGRO</h2>

Milagro TLS  has only been built and tested on Linux and Mac with the GCC tool chain.

First install the mpin-crypto library and then the mbed TLS library.

CMake is required to build the library and can usually be installed from
the operating system package manager. 

<ul type="disc">
  <li>sudo apt-get install cmake</li>
</ul>

If not, then you can download it from www.cmake.org


<h2>Compiling mpin-crypto</h2>

<li>See https://github.com/miracl/milagro-crypto/blob/master/README.md</li>


<h2>Compiling mbed TLS</h2>

<ol type="disc">
  <li>git clone https://github.com/miracl/milagro-tls</li>
  <li>cd mtls</li>
  <li>mkdir release</li>
  <li>cd release</li>
  <li>cmake -D AMCL_INSTALL_DIR=/opt/amcl ..</li>
  <li>make</li>
  <li>make test</li>
  <li>sudo make install</li>
</ol>


