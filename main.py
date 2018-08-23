
import dbscan_android_malware as dbs
import utils
import argparse


def main(data_hashes_dest, percentage_sample, ground_truth_dest, feature_vector_parent):

    apk_sha256_dict = dbs.create_sha256_dict(ground_truth_dest)

    feature_vector_hashes = utils.get_feature_vector_hashes(data_hashes_dest,
                                                            percentage_sample,
                                                            apk_sha256_dict,
                                                            ground_truth_dest,
                                                            leave_out_benign=False,
                                                            only_fake_installer=False,
                                                            top_three_malware=False)

    vocabulary = utils.build_vocab(feature_vector_hashes, feature_vector_parent)

    feature_vector_matrix, ground_truth = dbs.construct_feature_vector_matrix(
        vocabulary, feature_vector_hashes, apk_sha256_dict, feature_vector_parent
    )
    jaccard_distance_matrix = dbs.compute_jaccard_distance_matrix(feature_vector_matrix)

    min_pts = 30
    eps = 0.46

    utils.plot_knn_values(jaccard_distance_matrix, [min_pts], eps)

    dbs.run_dbscan_and_plot(eps, min_pts, jaccard_distance_matrix, ground_truth)

    dbs.print_dataset_stats(feature_vector_hashes, apk_sha256_dict, vocabulary)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run DBScanDroid')
    parser.add_argument("data_hashes_dest", help="Destination of application hash list")
    parser.add_argument("percentage_sample", help="Percentage of data sample to take")
    parser.add_argument("ground_truth_dest", help="Destination of ground truth csv")
    parser.add_argument("feature_vector_parent", help="Directory name where feature vector parent")

    args = parser.parse_args()

    main(args.data_hashes_dest, args.percentage_sample, args.ground_truth_dest, args.feature_vector_parent)