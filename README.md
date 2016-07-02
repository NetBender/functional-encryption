# functional-encryption
A Functional Encryption Scheme for Inner Products

### Usage
This implementation, made for educational purposes, allows you to edit the size of the inputs in order to see how the complexity changes.


In the **functional-enc.h** file, you'll find many definitions that you can use to see how the scheme behaves. The main ones are:
* *VECTORS*: number of the message vectors that will be generated;
* *VECTORS_LENGTH*: length of the vectors (x and y);
* *X_MSG_LENGTH*: size of each message in vector X (in bits);
* *Y_MSG_LENGTH*: size of each message in vector Y (in bits).

After every edit, you have to re-build the code in order to apply the changes.

### Prerequisites
In order to be built, you computer needs:
* GCC;
* the GNU MP Bignum Library.

In a Debian-based environment, you can simply:

* run `$ sudo apt-get install build-essential` to install GCC;

* download the latest GMP'stable release from [here](https://gmplib.org/#DOWNLOAD), unpack it and run the following commands:
    * `$ ./configure`;
    * `$ make`;
    * `$ make install`.

### How to build
Open a Terminal in the folder where you've downloaded the project and run

* `$ make` to build;

* `$ ./test-functional-enc` to run the code.

###Credits
This implementation is based on the content of the paper "Simple Functional Encryption Schemes
for Inner Products"(available [here](https://eprint.iacr.org/2015/017.pdf)) by [Michel Abdalla](mailto:michel.abdalla@ens.fr), [Florian Bourse](florian.bourse@ens.fr), [Angelo De Caro](angelo.decaro@ens.fr), and [David Pointcheval](david.pointcheval@ens.fr).

###License
This open-source software is published under the GNU General Public License (GNU GPL) version 3. Please refer to the "LICENSE" file of this project for the full text.
