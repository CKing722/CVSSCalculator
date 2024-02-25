def get_metric_input(prompt, options):
  """
  Helper function to get and validate user input for CVSS metrics.
  This function displays options for each metric for users to choose from.
  """
  print(prompt)
  for key, value in options.items():
      print(f"{key}: {value}")
  value = input("Enter your choice (e.g., N for NETWORK): ").strip().upper()
  while value not in options:
      print("Invalid input. Please try again.")
      value = input("Enter your choice (e.g., N for NETWORK): ").strip().upper()
  return options[value]

def calculate_base_score(AV, AC, PR, UI, S, C, I, A):
  """
  Calculate the CVSS Base Score using the provided metrics.
  """
  # Metric weights, directly using the values from user input
  weight = {
      'AV': {'NETWORK': 0.85, 'ADJACENT': 0.62, 'LOCAL': 0.55, 'PHYSICAL': 0.2},
      'AC': {'LOW': 0.77, 'HIGH': 0.44},
      'PR': {'NONE': 0.85, 'LOW': 0.62, 'HIGH': 0.27},
      'UI': {'NONE': 0.85, 'REQUIRED': 0.62},
      'S': {'UNCHANGED': 6.42, 'CHANGED': 7.52},
      'C': {'HIGH': 0.56, 'LOW': 0.22, 'NONE': 0},
      'I': {'HIGH': 0.56, 'LOW': 0.22, 'NONE': 0},
      'A': {'HIGH': 0.56, 'LOW': 0.22, 'NONE': 0},
  }

  # Convert full words to their corresponding numeric values for calculation
  AV_val = weight['AV'][AV]
  AC_val = weight['AC'][AC]
  PR_val = weight['PR'][PR]
  UI_val = weight['UI'][UI]
  S_val = weight['S'][S]
  C_val = weight['C'][C]
  I_val = weight['I'][I]
  A_val = weight['A'][A]

  # Calculating the impact and exploitability
  impact_base = 1 - ((1 - C_val) * (1 - I_val) * (1 - A_val))
  if S_val == 6.42:  # UNCHANGED
      impact = 6.42 * impact_base
  else:  # CHANGED
      impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base * 0.9731 - 0.02) ** 13

  exploitability = 8.22 * AV_val * AC_val * PR_val * UI_val

  # Calculating the base score
  if impact <= 0:
      base_score = 0
  else:
      if S_val == 6.42:  # UNCHANGED
          base_score = min((impact + exploitability), 10)
      else:  # CHANGED
          base_score = min(1.08 * (impact + exploitability), 10)

  return round(base_score, 1)

def main():
  # Define the options for each metric
  options = {
      'AV': {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"},
      'AC': {"L": "LOW", "H": "HIGH"},
      'PR': {"N": "NONE", "L": "LOW", "H": "HIGH"},
      'UI': {"N": "NONE", "R": "REQUIRED"},
      'S': {"U": "UNCHANGED", "C": "CHANGED"},
      'C': {"H": "HIGH", "L": "LOW", "N": "NONE"},
      'I': {"H": "HIGH", "L": "LOW", "N": "NONE"},
      'A': {"H": "HIGH", "L": "LOW", "N": "NONE"}
  }

  # Get user input for each metric
  AV = get_metric_input("Attack Vector (AV)", options['AV'])
  AC = get_metric_input("Attack Complexity (AC)", options['AC'])
  PR = get_metric_input("Privileges Required (PR)", options['PR'])
  UI = get_metric_input("User Interaction (UI)", options['UI'])
  S = get_metric_input("Scope (S)", options['S'])
  C = get_metric_input("Confidentiality (C)", options['C'])
  I = get_metric_input("Integrity (I)", options['I'])
  A = get_metric_input("Availability (A)", options['A'])

  # Calculate and print the Base Score
  base_score = calculate_base_score(AV, AC, PR, UI, S, C, I, A)
  print(f"CVSS Base Score: {base_score}")

if __name__ == "__main__":
  main()
