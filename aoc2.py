def is_safe(report):
    n = len(report)

    # Check if all differences between adjacent elements are between 1 and 3
    for i in range(n - 1):
        diff = abs(report[i + 1] - report[i])
        if diff < 1 or diff > 3:
            return False

    # Check if the report is either strictly increasing or strictly decreasing
    if all(report[i] < report[i + 1] for i in range(n - 1)):
        return True
    if all(report[i] > report[i + 1] for i in range(n - 1)):
        return True

    return False

def is_safe_with_dampener(report):
    # If the report is safe without changes, return True
    if is_safe(report):
        return True

    # Try removing each level and check if the remaining report is safe
    for i in range(len(report)):
        modified_report = report[:i] + report[i+1:]  # Remove the i-th level
        if is_safe(modified_report):
            return True

    return False

def count_safe_reports_with_dampener(reports):
    """
    Count the number of safe reports from a list of reports,
    considering the Problem Dampener.
    """
    safe_count = 0
    for report in reports:
        if is_safe_with_dampener(report):
            safe_count += 1
    return safe_count

# Example usage
input_data  = open("/home/pheonix/Desktop/DEV_bkup/Hybrid-Encryption/aoc2.txt","r").read()


# Parse the input into a list of lists
reports = [list(map(int, line.split())) for line in input_data.splitlines()]

# Calculate the number of safe reports considering the Problem Dampener
safe_count = count_safe_reports_with_dampener(reports)

print(f"Number of safe reports with Problem Dampener: {safe_count}")
