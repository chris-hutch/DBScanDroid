# DBScanDroid
####Shedding light on the application of Density-Based Clustering to Android Malware

This repository contains the code necessary to run DBScan against the Drebin Dataset

##Usage
The following parameters are required to run this program (in order):
* data_hashes_destination = file destination of text file containing sha256 hash identifers for apks
* percentage_sample = (currently not optional) what percentage of the passed data_hashes would you like to use
* grouth_truth_dest = file destination of sah256 to malware family
* feature_vector_parent = containing directory of the location of feature vectors for each application

This application requires access to the Drebin dataset and must be accessible to this script.

NB: The Drebin dataset has not been included and should be requested from https://www.sec.cs.tu-bs.de/~danarp/drebin/