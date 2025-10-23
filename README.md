# Script: initial_posture_assessment.sh
# Description: Performs a quick, high-impact scan on a subnet to discover easy-to-find
# security misconfigurations and information leakage, suitable for an initial security
# posture assessment.
#
# Usage: ./initial_posture_assessment.sh <subnet_cidr>
# Example: ./initial_posture_assessment.sh 10.0.0.0/24
# OR: sudo bash initial_posture_assessment.sh <subnet_cidr>
# Make executable: chmod +x initital_posture_assessment.sh
#                  ./initial_posture_assessment.sh
