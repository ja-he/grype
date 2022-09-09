import yardstick
from yardstick import store, comparison, artifact
from yardstick.cli import display
from typing import Optional
import sys
import re

from tabulate import tabulate

from dataclasses import dataclass, InitVar, field

# see the .yardstick.yaml configuration for details
result_sets = [
    # "pr-vs-latest-via-sbom",
    "pr-vs-latest-via-image"
]


@dataclass
class Gate:
    label_comparisons: InitVar[Optional[list[comparison.AgainstLabels]]]
    label_comparison_stats: InitVar[Optional[comparison.ImageToolLabelStats]]

    reasons: list[str] = field(default_factory=list)

    def __post_init__(self, label_comparisons: Optional[list[comparison.AgainstLabels]], label_comparison_stats: Optional[comparison.ImageToolLabelStats]):
        if not label_comparisons and not label_comparison_stats:
            return 
    
        reasons = []

        # - fail when current F1 score drops below last release F1 score (or F1 score is indeterminate)
        # - fail when indeterminate % > 10%
        # - fail when there is a rise in FNs
        latest_release_tool, current_tool = Gate._get_compare_tools(label_comparison_stats)

        latest_release_comparisons_by_image = {comp.config.image: comp for comp in label_comparisons if comp.config.tool == latest_release_tool }
        current_comparisons_by_image = {comp.config.image: comp for comp in label_comparisons if comp.config.tool == current_tool }

        for image, comp in current_comparisons_by_image.items():
            latest_f1_score = latest_release_comparisons_by_image[image].summary.f1_score
            current_f1_score = comp.summary.f1_score
            if current_f1_score < latest_f1_score:
                reasons.append(f"current F1 score is lower than the latest release F1 score: {bcolors.BOLD+bcolors.UNDERLINE}current={current_f1_score:0.2f} latest={latest_f1_score:0.2f}{bcolors.RESET} image={image}")

            if comp.summary.indeterminate_percent > 10:
                reasons.append(f"current indeterminate matches % is greater than 10%: {bcolors.BOLD+bcolors.UNDERLINE}current={comp.summary.indeterminate_percent:0.2f}%{bcolors.RESET} image={image}")
    
            latest_fns = latest_release_comparisons_by_image[image].summary.false_negatives
            current_fns = comp.summary.false_negatives
            if current_fns > latest_fns:
                reasons.append(f"current false negatives is greater than the latest release false negatives: {bcolors.BOLD+bcolors.UNDERLINE}current={current_fns} latest={latest_fns}{bcolors.RESET} image={image}")

        self.reasons = reasons

    def passed(self):
        return len(self.reasons) == 0

    @staticmethod
    def _get_compare_tools(label_comparison_stats: comparison.ImageToolLabelStats):
        if len(label_comparison_stats.tools) != 2:
            raise RuntimeError("expected 2 tools, got %s" % label_comparison_stats.tools)

        current_tool = None
        latest_release_tool = None
        for tool in label_comparison_stats.tools:
            if tool.endswith("latest"):
                latest_release_tool = tool
                continue
            current_tool = tool

        if latest_release_tool is None:
            raise ValueError("latest release tool not found")

        if current_tool is None:
            raise ValueError("current tool not found")
        return latest_release_tool, current_tool

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def show_results_used(results: list[artifact.ScanResult]):
    print(f"   Results used:")
    for idx, result in enumerate(results):
        branch = "├──"
        if idx == len(results) - 1:
            branch = "└──"
        print(f"    {branch} {result.ID} : {result.config.tool} against {result.config.image}")
    print()

def validate(result_set: str):
    print(f"{bcolors.HEADER}{bcolors.BOLD}Validating with {result_set!r}", bcolors.RESET)
    result_set_obj = store.result_set.load(name=result_set)
    descriptions = result_set_obj.descriptions
    for state in result_set_obj.state:
        print("   ", f"with {state.request.tool} against {state.request.image}")
    print()

    # do a relative comparison
    # - show comparison summary (no gating action)
    # - list out all individual match differences

    print(f"{bcolors.HEADER}Running relative comparison...", bcolors.RESET)
    relative_comparison = yardstick.compare_results(descriptions=descriptions)
    show_results_used(relative_comparison.results)

    # bail if there are no differences found
    if not sum([len(relative_comparison.unique[result.ID]) for result in relative_comparison.results]):
        print("no differences found between tool results")
        return Gate(None, None)

    # show the relative comparison results
    # display.preserved_matches(relative_comparison, details=False, summary=True, common=False)
    # print()

    # do a label comparison
    print(f"{bcolors.HEADER}Running comparison against labels...", bcolors.RESET)
    results, label_entries, comparisons_by_result_id, stats_by_image_tool_pair = yardstick.compare_results_against_labels(descriptions=descriptions)
    show_results_used(results)

    # display.label_comparison(
    #         results,
    #         comparisons_by_result_id,
    #         stats_by_image_tool_pair,
    #         show_fns=True,
    #         show_summaries=True,
    #     )

    # show the relative comparison unique differences paired up with label conclusions (TP/FP/FN/TN/Unknown)
    all_rows: list[list[Any]] = []
    for result in relative_comparison.results:
        label_comparison = comparisons_by_result_id[result.ID]
        for unique_match in relative_comparison.unique[result.ID]:
            labels = label_comparison.labels_by_match[unique_match.ID]
            if not labels:
                label = "(unknown)"
            elif len(set(labels)) > 1:
                label = ", ".join([l.name for l in labels])
            else:
                label = labels[0].name
            
            color = ""
            if label == artifact.Label.TruePositive.name:
                color = bcolors.OKBLUE
            elif artifact.Label.FalsePositive.name in label:
                color = bcolors.WARNING

            all_rows.append(
                [
                    f"{color}{result.config.tool} ONLY{bcolors.RESET}",
                    f"{color}{unique_match.package.name}@{unique_match.package.version}{bcolors.RESET}",
                    f"{color}{unique_match.vulnerability.id}{bcolors.RESET}",
                    f"{color}{label}{bcolors.RESET}",
                ]
            )

    def escape_ansi(line):
        ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', line)

    # sort but don't consider ansi escape codes
    all_rows = sorted(all_rows, key=lambda x: escape_ansi(str(x[0]+x[1]+x[2]+x[3])))
    print("Match differences between tooling (with labels):")
    indent = "   "
    print(indent + tabulate([["TOOL PARTITION", "PACKAGE", "VULNERABILITY", "LABEL"]]+all_rows, tablefmt="plain").replace("\n", "\n" + indent) + "\n")

    # populate the quality gate with data that can evaluate pass/fail conditions
    return Gate(label_comparisons=comparisons_by_result_id.values(), label_comparison_stats=stats_by_image_tool_pair)

def main():
    gates = []
    for result_set in result_sets:
        gates.append(validate(result_set))
        print()
    
    failure = not all([gate.passed() for gate in gates])
    if failure:
        print("Reasons for quality gate failure:")
    for gate in gates:
        for reason in gate.reasons:
            print(f"   - {reason}")

    if failure:
        print()
        print(f"{bcolors.FAIL}{bcolors.BOLD}Quality gate FAILED{bcolors.RESET}")
        sys.exit(1)
    else:
        print(f"{bcolors.OKGREEN}{bcolors.BOLD}Quality gate passed!{bcolors.RESET}")


if __name__ == '__main__':
    main()