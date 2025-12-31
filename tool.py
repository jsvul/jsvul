import argparse
import logging
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

import filter_datasets.nvd.collect_all_cves as nvd_cac
import filter_datasets.crossvul.filter_data as crossvul_fd
import filter_datasets.cvefixes.filter_data as cvefixes_fd
import filter_datasets.js_vuln.filter_csv as js_vuln_fc
import filter_datasets.js_vuln.filter_vu_blob as js_vuln_fvb
import filter_datasets.js_vuln.merge_csv_and_vu_blob as js_vuln_mcavb
import filter_datasets.js_vuln.filter_data as js_vuln_fd
import filter_datasets.nvd.filter_data as nvd_fd
import filter_datasets.ossf_cve_benchmark.filter_data as ossf_fd
import filter_datasets.osv.filter_data as osv_fd
import filter_datasets.secbenchjs.filter_data as secbenchjs_fd
import merge_datasets.merge as merge
import merge_datasets.filter_merged_data as filter_merged
import merge_datasets.find_duplications as find_dup
import merge_datasets.filter_duplications as filter_dup
import merge_datasets.remove_duplications as remove_dup
import merge_datasets.fix.fix_files_in_dataset as fix_files
import merge_datasets.copy_folder as copy_folder
import merge_datasets.format.run_eslint as run_eslint
import merge_datasets.format.run_prettier as run_prettier
import merge_datasets.generate_new_patches as generate_new_patches
import postprocess.extract_functions as extract_functions
import postprocess.label_functions as label_functions
import postprocess.onefunc_and_nvdcheck as onefunc_and_nvdcheck
import postprocess.remove_function_duplications as remove_function_duplications
import use_dataset.unify_dataset as unify_dataset
from filter_datasets.util.statistics import list_files, has_files
from util.common import get_data_dirs, play_notification_sound

load_dotenv()

timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
LOG_FILE = Path(__file__).parent / "logs" / f"{timestamp}.log"
LOG_FILE.parent.mkdir(exist_ok=True)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

ALL_DATASETS = ["nvd", "osv", "ossf_cve_benchmark", "js_vuln", "cvefixes", "crossvul", "secbenchjs"]
ALL_FILTERS = {
    "added_removed": filter_merged.filter_added_removed_files,
    "irrelevant": filter_merged.filter_irrelevant_files,
    "test": filter_merged.filter_test_files,
    "minified": filter_merged.filter_minified_files
}


def data_collection(datasets: list):
    work_dir = os.environ["WORK_DIR"]
    dataset_texts = {
        "crossvul": f"Copy CrossVul's metadata.json to '{work_dir}/_data/crossvul/metadata.json'",
        "cvefixes": f"Copy CveFixes' CVEfixes.db to '{work_dir}/_data/cvefixes/CVEfixes.db'",
        "js_vuln": f"Copy js_vuln's vu_blob.json to '{work_dir}/_data/js_vuln/vu_blob.json' and JSVulnerabilityDataSet-1.0.csv to '{work_dir}/_data/js_vuln/JSVulnerabilityDataSet-1.0.csv'",
        "ossf_cve_benchmark": f"Copy ossf_cve_benchmark's cve jsons to '{work_dir}/_data/ossf_cve_benchmark/*.json'",
        "osv": f"Copy OSV's cve jsons to '{work_dir}/_data/osv/*.json'",
        "secbenchjs": f"Copy secbench's cwe folders to '{work_dir}/_data/secbenchjs/[folder_name]'",
    }
    for dataset in datasets:
        if dataset not in dataset_texts:
            continue

        _, _, data_dir = get_data_dirs(dataset)
        if data_dir.exists():
            continue

        logger.info(f"{dataset_texts[dataset]} then press enter to continue...")
        input()

    if "nvd" in datasets:
        _, _, data_dir = get_data_dirs("nvd")
        if not data_dir.exists():
            print("Collecting all CVEs from NVD (this may take for a while)...")
            nvd_cac.main(data_dir=data_dir)
            print("Done collecting CVEs from NVD.")


def filter_data(datasets: list, force: bool):
    filter_data_functions = {
        "crossvul": [crossvul_fd.filter_js_files],
        "cvefixes": [cvefixes_fd.filter_js_files],
        "js_vuln": [js_vuln_fc.process_csv, js_vuln_fvb.main, js_vuln_mcavb.main, js_vuln_fd.filter_js_files],
        "nvd": [nvd_fd.filter_js_files],
        "ossf_cve_benchmark": [ossf_fd.filter_js_files],
        "osv": [osv_fd.filter_js_files],
        "secbenchjs": [secbenchjs_fd.filter_js_files],
    }
    for dataset in datasets:
        _, collected_info_dir, data_dir = get_data_dirs(dataset)
        if collected_info_dir.exists() and not force:
            continue

        if force:
            shutil.rmtree(collected_info_dir, ignore_errors=True)

        for filter_func in filter_data_functions[dataset]:
            filter_func(data_dir, collected_info_dir)


def merge_data(dir_name_to: str, datasets: list, force=False):
    _, _, data_dir = get_data_dirs(dir_name_to)
    if data_dir.exists() and not force:
        logger.info("============ Merge Data step - Skipped ============")
        return

    logger.info("============ Merge Data step - Start ============")
    if force:
        shutil.rmtree(data_dir, ignore_errors=True)

    merge.main(datasets=datasets, data_dir=data_dir)
    logger.info("============ Merge Data step - Done ============")


def filter_merged_data(dir_name_from: str, dir_name_to: str, filters: list, force=False):
    _, _, data_dir_to = get_data_dirs(dir_name_to)
    if data_dir_to.exists() and not force:
        logger.info("============ Filter Merged Data step - Skipped ============")
        return

    logger.info("============ Filter Merged Data step - Start ============")
    if force:
        shutil.rmtree(data_dir_to, ignore_errors=True)

    _, _, data_dir_from = get_data_dirs(dir_name_from)
    filter_merged.main(data_dir_from=data_dir_from, data_dir_to=data_dir_to, filters=filters)
    logger.info("============ Filter Merged Data step - Done ============")


def remove_duplicated_commits(dir_name_from: str, dir_name_to: str, force=False):
    _, _, data_dir_to = get_data_dirs(dir_name_to)
    if data_dir_to.exists() and not force:
        logger.info("============ Commit Duplication Removal step - Skipped ============")
        return

    logger.info("============ Commit Duplication Removal step - Start ============")
    if force:
        shutil.rmtree(data_dir_to, ignore_errors=True)

    _, collected_info_dir, data_dir_from = get_data_dirs(dir_name_from)
    find_dup.main(data_dir=data_dir_from, collected_info_dir=collected_info_dir)
    filter_dup.main(data_dir=data_dir_from, collected_info_dir=collected_info_dir)
    remove_dup.main(data_dir_from=data_dir_from, data_dir_to=data_dir_to, collected_info_dir=collected_info_dir)
    logger.info("============ Commit Duplication Removal step - Done ============")


def fix_wrong_files(dir_name_from: str, dir_name_to: str, force=False):
    _, _, data_dir_to = get_data_dirs(dir_name_to)
    if data_dir_to.exists() and not force:
        logger.info("============ Fix Files step - Skipped ============")
        return

    logger.info("============ Fix Files step - Start ============")
    if force:
        shutil.rmtree(data_dir_to, ignore_errors=True)

    _, _, data_dir_from = get_data_dirs(dir_name_from)
    fix_files.main(from_dir=data_dir_from, to_dir=data_dir_to)
    logger.info("============ Fix Files step - Done ============")


def format_files_with_eslint(dir_name_from: str, dir_name_to: str, force=False):
    _, _, data_dir_to = get_data_dirs(dir_name_to)
    if data_dir_to.exists() and not force:
        logger.info("============ Eslint Format step - Skipped ============")
        return

    logger.info("============ Eslint Format step - Start ============")
    if force:
        shutil.rmtree(data_dir_to, ignore_errors=True)

        run_cache_dir, _, _ = get_data_dirs("run")
        shutil.rmtree(run_cache_dir / "eslint", ignore_errors=True)

    _, _, data_dir_from = get_data_dirs(dir_name_from)
    copy_folder.main(data_dir_from, data_dir_to)

    run_eslint.main(data_dir=data_dir_to)
    logger.info("============ Eslint Format step - Done ============")


def format_files_with_prettier(dir_name_from: str, dir_name_to: str, force=False):
    _, _, data_dir_to = get_data_dirs(dir_name_to)
    if data_dir_to.exists() and not force:
        logger.info("============ Prettier Format step - Skipped ============")
        return

    logger.info("============ Prettier Format step - Start ============")
    if force:
        shutil.rmtree(data_dir_to, ignore_errors=True)

        run_cache_dir, _, _ = get_data_dirs("run")
        shutil.rmtree(run_cache_dir / "prettier", ignore_errors=True)

    _, _, data_dir_from = get_data_dirs(dir_name_from)
    copy_folder.main(data_dir_from, data_dir_to)

    run_prettier.main(data_dir=data_dir_to)
    logger.info("============ Prettier Format step - Done ============")


def generate_diffs(dir_name: str, force=False):
    _, _, data_dir = get_data_dirs(dir_name)
    patches = has_files(data_dir / "files", ".patch")
    if patches and not force:
        logger.info("============ New Diff Generation step - Skipped ============")
        return

    logger.info("============ New Diff Generation step - Start ============")
    if force:
        for patch in list_files(data_dir / "files", ".patch"):
            patch.unlink()

        generation_cache_dir, _, _ = get_data_dirs("patches_generated")
        shutil.rmtree(generation_cache_dir, ignore_errors=True)

    generate_new_patches.main(data_dir=data_dir)
    logger.info("============ New Diff Generation step - Done ============")


def extract_and_label_functions(dir_name: str, force=False):
    _, _, data_dir = get_data_dirs(dir_name)
    if (data_dir / "functions").exists() and not force:
        logger.info("============ Function Extraction & Labeling step - Skipped ============")
        return

    logger.info("============= Function Extraction & Labeling step - Start =============")
    if force:
        shutil.rmtree(data_dir / "functions", ignore_errors=True)

    extract_functions.main(data_dir=data_dir)
    label_functions.main(data_dir=data_dir)
    logger.info("============== Function Extraction & Labeling step - Done =============")


def filter_files_with_onefunc_and_nvdcheck(dir_name_from: str, dir_name_to: str, dedup: bool, force=False):
    _, _, data_dir_to = get_data_dirs(dir_name_to)
    if data_dir_to.exists() and not force:
        logger.info("============ onefunc and nvdcheck step - Skipped ============")
        return

    logger.info("============ onefunc and nvdcheck step - Start ============")
    if force:
        shutil.rmtree(data_dir_to, ignore_errors=True)

    _, _, data_dir_from = get_data_dirs(dir_name_from)
    onefunc_and_nvdcheck.main(data_dir_from=data_dir_from, data_dir_to=data_dir_to, dedup=dedup)
    logger.info("============ onefunc and nvdcheck step - Done ============")


def remove_duplicated_functions(dir_name_from: str, dir_name_to: str, force=False):
    _, _, data_dir_to = get_data_dirs(dir_name_to)
    if data_dir_to.exists() and not force:
        logger.info("============ Remove Duplicated Functions step - Skipped ============")
        return

    logger.info("============ Remove Duplicated Functions step - Start ============")
    logger.info(f'dir_name_from="{dir_name_from}", dir_name_to="{dir_name_to}"')
    if force:
        shutil.rmtree(data_dir_to, ignore_errors=True)

    _, _, data_dir_from = get_data_dirs(dir_name_from)
    remove_function_duplications.main(data_dir_from=data_dir_from, data_dir_to=data_dir_to)
    logger.info("============ Remove Duplicated Functions step - Done ============")


def run_unifying(dir_name_from: str, data_dir_to: Path, distributions: list[float], npo: bool, force=False):
    if data_dir_to.exists() and not force:
        logger.info("============ Unify step - Skipped ============")
        return

    logger.info("============ Unify step - Start ============")
    if force:
        shutil.rmtree(data_dir_to, ignore_errors=True)

    _, _, data_dir_from = get_data_dirs(dir_name_from)
    unify_dataset.main(data_dir=data_dir_from, jsonl_dir=data_dir_to, distributions=distributions, only_pairs=npo)
    logger.info("============ Unify step - Done ============")


def _add_list_arg(parser, names, label, valid_options):
    parser.add_argument(
        *names, nargs='+', default=None,
        help=f'Space separated list of {label}. Available options are: all, {", ".join(valid_options)}'
    )


def _validate_list_arg(arg_list, valid_options, arg_name, parser):
    if not arg_list:
        return

    if "all" in arg_list:
        if len(arg_list) > 1:
            parser.error(f"When 'all' is specified for {arg_name} argument, no other options should be provided.")

    for flt in arg_list:
        if flt not in valid_options:
            parser.error(f"Invalid {arg_name} value: {flt}. Valid options are: all, {', '.join(valid_options)}")


def _log_args(args):
    logger.info("=============== Run Values ================")
    if not os.getenv("DOCKER"):
        if args and args.work_dir:
            logger.info(f"work-dir: {args.work_dir}")

        else:
            logger.info(f"work-dir: {Path.cwd()}")

    if not args or args.merge:
        if args and args.datasets and "all" not in args.datasets:
            logger.info(f"datasets: {args.datasets}")

        else:
            logger.info(f"datasets: {ALL_DATASETS}")

    if not args or args.process:
        if args and args.filters and "all" not in args.filters:
            logger.info(f"filters: {args.filters}")

        else:
            logger.info(f"filters: {list(ALL_FILTERS.keys())}")

    if not args or args.unify:
        if args and args.unify_dir:
            logger.info(f"unify-dir: {args.unify_dir}")

        else:
            _, _, unify_out_dir = get_data_dirs("unified_data")
            logger.info(f"unify-dir: {unify_out_dir}")

        logger.info(f"unify-split: {(args and args.unify_split) or [80, 10, 10]}")

    logger.info("===========================================")


def parse_args():
    if len(sys.argv) == 1:
        logger.info("No arguments were provided. Defaulting to RUN ALL steps.")
        return None

    parser = argparse.ArgumentParser(description="Pipeline processing tool.")
    if not os.getenv("DOCKER"):
        parser.add_argument('-w', '--work-dir', type=Path, help='Work directory', default=None)

    parser.add_argument('-m', '--merge', action='store_true', help='Run merge step')
    _add_list_arg(parser, ['-d', '--datasets'], "datasets", ALL_DATASETS)

    parser.add_argument('-p', '--process', action='store_true', help='Run our filtering steps')
    _add_list_arg(parser, ['--filters'], "filters", ALL_FILTERS)

    parser.add_argument('-u', '--unify', action='store_true', help='Run the unify step')
    parser.add_argument('--unify-dir', type=Path, help='Unify output directory', default=None)
    parser.add_argument(
        '--unify-split', nargs='+', default=None,
        help=f'Space separated list of numbers. Defines the split of vulnerable functions in the unify step.'
    )
    parser.add_argument('--unify-npo', action='store_true', help='Run the unify step only for paired examples')

    parser.add_argument('-f', '--force', action='store_true', help='Ignore completion checks and force re-processing')

    args = parser.parse_args()

    if getattr(args, "work_dir", None):
        if not args.work_dir.exists():
            args.work_dir.mkdir(parents=True, exist_ok=True)

        if not args.work_dir.is_dir():
            parser.error(f"work-dir '{args.work_dir}' is not a directory.")

    if args.unify_dir:
        if not args.unify:
            parser.error(
                "unify-dir argument is only valid when unify is specified. Default is `[work_dir]/unified_data`"
            )

        if args.unify_dir.exists() and not args.unify_dir.is_dir():
            parser.error(f"unify-dir '{args.unify_dir}' is not a directory.")

    if args.unify_split:
        if not args.unify:
            parser.error("unify-split argument is only valid when unify is specified. Default is '80 10 10'")

        try:
            try:
                split_values = [int(s) for s in args.unify_split]
            except:
                split_values = [float(s) for s in args.unify_split]

            if any(s < 0 for s in split_values) or sum(split_values) <= 0:
                raise ValueError

            args.unify_split = split_values

        except ValueError:
            parser.error(
                "unify-split must be a list of positive numbers representing the split ratios "
                "(e.g., '0.8 0.1 0.1' or '40 5 5')."
            )

    _validate_list_arg(args.datasets, ALL_DATASETS, "datasets", parser)
    _validate_list_arg(args.filters, ALL_FILTERS, "filters", parser)

    return args


def main():
    args = parse_args()
    _log_args(args)
    try:
        if not os.getenv("DOCKER"):
            if args and args.work_dir:
                os.environ["WORK_DIR"] = str(args.work_dir)

            else:
                os.environ["WORK_DIR"] = str(Path.cwd())

        merge_out = "merged_data"
        if not args or args.merge:
            if not args or not args.datasets or "all" in args.datasets:
                datasets = ALL_DATASETS

            else:
                datasets = args.datasets

            data_collection(datasets=datasets)
            filter_data(datasets=datasets, force=args and args.force)
            merge_data(dir_name_to=merge_out, datasets=datasets, force=args and args.force)

        final_out = "08_final"
        if not args or args.process:
            data_filters = []
            if not args or not args.filters or "all" in args.filters:
                data_filters = ALL_FILTERS.values()

            else:
                for flt in args.filters:
                    data_filters.append(ALL_FILTERS[flt])

            filter_out = "01_filtered"
            filter_merged_data(
                dir_name_from=merge_out, dir_name_to=filter_out, filters=data_filters, force=args and args.force
            )

            sha_dedup_out = "02_no_dup"
            remove_duplicated_commits(dir_name_from=filter_out, dir_name_to=sha_dedup_out, force=args and args.force)

            fix_out = "03_fixed"
            fix_wrong_files(dir_name_from=sha_dedup_out, dir_name_to=fix_out, force=args and args.force)

            eslint_out = "04_eslint"
            format_files_with_eslint(dir_name_from=fix_out, dir_name_to=eslint_out, force=args and args.force)

            prettier_out = "05_prettier"
            format_files_with_prettier(dir_name_from=eslint_out, dir_name_to=prettier_out, force=args and args.force)
            generate_diffs(dir_name=prettier_out, force=args and args.force)

            formatted_dedup_out = "06_no_dup"
            remove_duplicated_commits(
                dir_name_from=prettier_out, dir_name_to=formatted_dedup_out, force=args and args.force
            )
            extract_and_label_functions(dir_name=formatted_dedup_out, force=args and args.force)

            of_nvdc_out = "07_of_nvdc"
            filter_files_with_onefunc_and_nvdcheck(
                dir_name_from=formatted_dedup_out, dir_name_to=of_nvdc_out, dedup=True, force=args and args.force
            )

            remove_duplicated_functions(dir_name_from=of_nvdc_out, dir_name_to=final_out, force=args and args.force)

        if not args or args.unify:
            unify_out_dir = args and args.unify_dir
            if not unify_out_dir:
                _, _, unify_out_dir = get_data_dirs("unified_data")

            run_unifying(
                dir_name_from=final_out,
                data_dir_to=unify_out_dir,
                distributions=(args and args.unify_split) or [80, 10, 10],
                npo=args and args.unify_npo,
                force=args and args.force,
            )

    except Exception as error:
        logger.error(error)
        play_notification_sound()


if __name__ == "__main__":
    main()
