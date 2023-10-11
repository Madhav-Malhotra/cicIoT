# Exploring the CIC-IoT-2023 Dataset

The Canadian Insitute of Cybersecurity at the University of New Brunswick published the open source [CIC-IoT-2023 dataset](https://www.kaggle.com/datasets/madhavmalhotra/unb-cic-iot-dataset). This dataset promotes **research on how to detect 7 kinds of cyberattacks across 100 IoT devices**.

Leading a [team of 15 at the University of Waterloo](https://wataicyber.substack.com/), this repository contains useful notebooks for sampling, preprocessing, visualising, and training models on the CIC-IoT-2023 dataset.

![We've republished the dataset on Kaggle to make it easier to use](preview.png)

### Notebook descriptions
1. `downsampling.ipynb` - This notebook samples 0.1, 0.5, 1, 5, and 10% of the rows from each cyberattack class from the dataset. This reduces the dataset size from 14GB to 12-600 MB, making it easier to perform feature visualisation and feature selection. [Kaggle live](https://www.kaggle.com/code/madhavmalhotra/creating-a-smaller-dataset-for-ciciot2023)
2. 

### Useful Links
1. [CIC-IoT-2023 Dataset on Kaggle](https://www.kaggle.com/datasets/madhavmalhotra/unb-cic-iot-dataset)
2. [Our team blog has more details about the notebooks](https://wataicyber.substack.com/)
3. [The original paper describing the dataset](https://www.mdpi.com/1424-8220/23/13/5941)