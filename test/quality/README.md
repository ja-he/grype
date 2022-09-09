# Match quality testing

This form of testing compares the results from various releases of grype using a
static set of reference container images. The kinds of comparisons made are:

1) "relative": find the vulnerability matching differences between both tools
   for a given image. This helps identify when a change has occurred in matching
   behavior and where the changes are.

2) "against labels": pair each tool results for an image with ground truth. This
   helps identify how well the matching behavior is performing (did it get
   better or worse).

We do these comparisons with the following tool profiles:

a) latest released version of grype vs a local development version of grype (via
the CURRENT_GRYPE_COMMIT env var) using the container images directly b) same as
(a) except that a static SBOM is used as input instead of the raw container
images

## Getting started

To capture raw tool output and store into the local `.yardstick` directory for
further analysis:
```
make capture
```

To analyze the tool output and evaluate a pass/fail result:
```
make validate
```

A pass/fail result is shown in the output with reasons for the failure being
listed explicitly.

## What is the quality gate criteria

The label comparison results are used to determine a pass/fail result,
specifically with the following criteria:

 - fail when current grype F1 score drops below last grype release F1 score (or
   F1 score is indeterminate)
 - fail when the indeterminate matches % > 10% in the current grype results
 - fail when there is a rise in FNs relative to the results from the last grype
   release
 - otherwise, pass

F1 score is the primary way that tool matching performance is characterized. F1
score combines the TP, FP, and FN counts into a single metric between 0 and 1.
Ideally the F1 score for an image-tool pair should be 1. F1 score is a good way
to summarize the matching performance but does not explain why the matching
performance is what it is.

Indeterminate matches are matches from results that could not be pared with a
label (TP or FP). This could also mean that multiple conflicting labels were
found for the a single match. The more indeterminate matches there are the less
confident you can be about the F1 score. Ideally there should be 0 indeterminate
matches, but this is difficult to achieve since vulnerability data is constantly
changing. The effects of changes have been dampened by ignoring vulnerability
results beyond a particular year (currently, only CVEs assigned on or before
2020 are considered during comparisons).

False negatives represent matches that should have been made by the tool but
were missed. We should always make certain that this value does not increase
between releases of grype.
