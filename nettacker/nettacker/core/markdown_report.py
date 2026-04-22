def generate_markdown_report(results, output_file="output.md"):
    """
    Generate a simple markdown report from scan results.
    """
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("# Nettacker Scan Report\n\n")

            if not results:
                f.write("No results found.\n")
                return

            for item in results:
                f.write(f"- {str(item)}\n")

    except Exception as e:
        print(f"Error generating markdown report: {e}")
