import operator
from collections import OrderedDict
from itertools import dropwhile
from sklearn.neighbors import NearestNeighbors
from collections import Counter
import matplotlib.pyplot as plt
from sklearn import metrics

import numpy as np

def get_feature_vector_hashes(data_split: str,
                              percent_to_retrieve: float,
                              apk_sha256_dict: dict,
                              ground_truth_dest: str,
                              leave_out_benign=False,
                              only_fake_installer=False,
                              top_three_malware=False,
                              minimum_applications_per_malware_family=10):


    ground_truth = np.loadtxt(ground_truth_dest, delimiter=",", skiprows=1, dtype=str)

    def _top_three_malware():
        with open(data_split, mode='r') as data:
            feature_vector_hashes = []

            for line in data:
                if len(feature_vector_hashes) >= (128994 * percent_to_retrieve):
                    break

                if line.rsplit() in ground_truth[:, 0]:
                    feature_vector_hashes.append(line.rsplit()[0])

            apk_sha256_dict_adjust = {k: apk_sha256_dict[k] for k in feature_vector_hashes if k in apk_sha256_dict}
            family_count = Counter(apk_sha256_dict_adjust.values())

            family_count = sorted(family_count.items(), key=operator.itemgetter(1), reverse=True)
            family_count = family_count[0:3]
            apk_sha256_dict_adjust = {
                k: apk_sha256_dict_adjust[k] for k in apk_sha256_dict_adjust.keys()
                if apk_sha256_dict_adjust[k] in
                   [i[0] for i in family_count]
            }

            return list(apk_sha256_dict_adjust.keys())

    def _weighted_benign_fake_installer():
        with open(data_split, mode='r') as split_1:
            feature_vector_hashes = []

            for line in split_1:
                if len(feature_vector_hashes) >= (128994 * percent_to_retrieve):
                    break

                if line.rsplit() not in ground_truth[:, 0]:
                    feature_vector_hashes.append(line.rsplit()[0])

            apk_sha256_dict_adjust = {k: apk_sha256_dict[k] for k, v in apk_sha256_dict.items() if v == "FakeInstaller"}
            apk_sha256_dict_adjust = {k: apk_sha256_dict_adjust[k] for k in sorted(apk_sha256_dict_adjust.keys())[:50]}
            feature_vector_hashes.extend(list(apk_sha256_dict_adjust.keys()))
            return feature_vector_hashes

    if only_fake_installer:
        return _weighted_benign_fake_installer()
    elif top_three_malware:
        return _top_three_malware()
    else:
        with open(data_split, mode='r') as split_1:
            feature_vector_hashes = []

            for line in split_1:
                if len(feature_vector_hashes) >= (128994 * percent_to_retrieve):
                    break

                feature_vector_hashes.append(line.rsplit()[0])

            apk_sha256_dict_adjust = {k: apk_sha256_dict[k] for k in feature_vector_hashes if k in apk_sha256_dict}
            family_count = Counter(apk_sha256_dict_adjust.values())

            for key, count in dropwhile(lambda key_count: key_count[1] >= minimum_applications_per_malware_family, family_count.most_common()):
                del family_count[key]

            if leave_out_benign:
                return list(apk_sha256_dict_adjust.keys())
            else:
                for hash in feature_vector_hashes:
                    if hash in ground_truth[:, 0]:
                        if hash not in apk_sha256_dict_adjust:
                            feature_vector_hashes.remove(hash)

            return feature_vector_hashes


def build_feature_vectors(file: str, feature_vector_parent: str):
    application_feature_set = []

    with open(feature_vector_parent + "/" + file) as file_feature_vectors:
        for line in [line.rstrip() for line in file_feature_vectors]:
            split_line = line.split("::")
            # Avoid operating on empty lines which don't contain feature and identifier
            if not len(split_line) == 2:
                continue

            if split_line[0] in ["activity", "service_receiver", "provider", "intent", "permission", "feature"]:
                application_feature_set.append(split_line[1])

        return application_feature_set


def build_vocab(*files, feature_vector_parent=None):

    hardware_comp_dict = {}  # S1
    requested_perms_dict = {}  # S2
    app_components = {}  # S3
    intent_filter_dict = {}  # S4
    all_feature_dict = OrderedDict()

    for idxx, arg in enumerate(files):
        for idxy, file in enumerate(arg):
            with open(feature_vector_parent + "/" + file) as file_feature_vectors:
                for line in [line.rstrip() for line in file_feature_vectors]:
                    split_line = line.split("::")
                    feature_set_identifier = split_line[0]
                    # Avoid operating on empty lines which don't contain feature and identifier
                    if not len(split_line) == 2:
                        continue
                    if feature_set_identifier == "activity" and split_line[1] not in app_components:
                        app_components[split_line[1]] = 1
                    elif feature_set_identifier == "service_receiver" and split_line[1] not in app_components:
                        app_components[split_line[1]] = 1
                    elif feature_set_identifier == "provider" and split_line[1] not in app_components:
                        app_components[split_line[1]] = 1
                    elif feature_set_identifier == "intent" and split_line[1] not in intent_filter_dict:
                        intent_filter_dict[split_line[1]] = 1
                    elif feature_set_identifier == "permission" and split_line[1] not in requested_perms_dict:
                        requested_perms_dict[split_line[1]] = 1
                    elif feature_set_identifier == "feature" and split_line[1] not in hardware_comp_dict:
                        hardware_comp_dict[split_line[1]] = 1

            all_feature_dict.update(hardware_comp_dict)
            all_feature_dict.update(requested_perms_dict)
            all_feature_dict.update(app_components)
            all_feature_dict.update(intent_filter_dict)
            print("Analysed from set ({}) {}/{}".format(idxx + 1, idxy + 1, len(arg)))

    return all_feature_dict


def plot_knn_values(X, k_values, eps=None):
    for k in k_values:
        # K + 1 as neighbours does not count index point whilst DSBSCAN range query does
        nbrs = NearestNeighbors(n_neighbors=k + 1, n_jobs=-1).fit(X)
        distances, indicies = nbrs.kneighbors(X)
        distances = np.sort(distances, axis=0)
        distances = distances[:, k - 1]
        # distances = distances[::-1]
        plt.ylabel('{}-NN Distance'.format(k_values[0]))
        plt.xlabel('Points (application) sorted by distance')
        plt.plot(distances, label="k (minPts) = {}".format(k))
        plt.axhline(y=eps, xmin=0.0, xmax=1.0, linestyle='--', color='k', linewidth=0.8)
    plt.legend()
    plt.show()


def delete_row_csr(mat, i):
    n = mat.indptr[i + 1] - mat.indptr[i]
    if n > 0:
        mat.data[mat.indptr[i]:-n] = mat.data[mat.indptr[i + 1]:]
        mat.data = mat.data[:-n]
        mat.indices[mat.indptr[i]:-n] = mat.indices[mat.indptr[i + 1]:]
        mat.indices = mat.indices[:-n]
    mat.indptr[i:-1] = mat.indptr[i + 1:]
    mat.indptr[i:] -= n
    mat.indptr = mat.indptr[:-1]
    mat._shape = (mat._shape[0] - 1, mat._shape[1])

'''
    Purity score impl -> https://stackoverflow.com/questions/34047540/python-clustering-purity-metric/51672699#51672699
'''
def purity_score(y_true, y_pred):
    # compute contingency matrix (also called confusion matrix)
    confusion_matrix = metrics.confusion_matrix(y_true, y_pred)
    # return purity
    return np.sum(np.amax(confusion_matrix, axis=0)) / np.sum(confusion_matrix)
