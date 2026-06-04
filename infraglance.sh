#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${1:-${SCRIPT_DIR}/infraglance.conf}"
COMMAND="run"
if [[ "${1:-}" == "--check" ]]; then
  COMMAND="check"
  CONFIG_FILE="${2:-${SCRIPT_DIR}/infraglance.conf}"
fi

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

safe_name() {
  local value="$1"
  value="${value//[^A-Za-z0-9_]/_}"
  printf '%s' "${value}"
}

var_exists() {
  declare -p "$1" >/dev/null 2>&1
}

load_config() {
  [[ -f "${CONFIG_FILE}" ]] || die "Config file not found: ${CONFIG_FILE}. Copy infraglance.conf.example to infraglance.conf first."
  # shellcheck source=/dev/null
  source "${CONFIG_FILE}"

  : "${REPORT_TITLE:=InfraGlance}"
  : "${OUTPUT_DIR:=${SCRIPT_DIR}/site}"
  : "${WORK_DIR:=${SCRIPT_DIR}/data}"
  : "${S3_BUCKET:=}"
  : "${S3_PREFIX:=infraglance}"
  : "${S3_PROFILE:=}"
  : "${PARTITION:=auto}"
  : "${ENVIRONMENT_TAG_KEY:=Environment}"
  : "${AUTO_DISCOVER_VPCS:=true}"
  : "${PRICING_FILE:=${SCRIPT_DIR}/pricing.json}"
  : "${MONTHLY_HOURS:=730}"
  : "${STOPPED_AMBER_DAYS:=7}"
  : "${STOPPED_RED_DAYS:=30}"
  : "${REDACT_PRIVATE_IPS:=false}"
  : "${REDACT_PUBLIC_IPS:=false}"
  : "${REDACT_INSTANCE_NAMES:=false}"
  : "${REDACT_DB_NAMES:=false}"
  : "${REDACT_VPC_CIDRS:=false}"

  [[ ${#ACCOUNTS[@]} -gt 0 ]] || die "ACCOUNTS cannot be empty"
  [[ ${#ENVIRONMENTS[@]} -gt 0 ]] || die "ENVIRONMENTS cannot be empty"
  [[ "${PARTITION}" == "auto" || "${PARTITION}" == "aws" || "${PARTITION}" == "aws-us-gov" ]] || die "PARTITION must be auto, aws, or aws-us-gov"
}

account_var() {
  local account_key
  account_key="$(safe_name "$1")"
  printf 'ACCOUNT_%s_%s' "${account_key}" "$2"
}

account_value() {
  local var_name
  var_name="$(account_var "$1" "$2")"
  printf '%s' "${!var_name:-}"
}

account_label() {
  local label
  label="$(account_value "$1" "LABEL")"
  [[ -n "${label}" ]] && printf '%s' "${label}" || printf '%s' "$1"
}

account_regions_var() {
  account_var "$1" "REGIONS"
}

partition_regions() {
  printf '%s\n' "us-gov-west-1" "us-gov-east-1"
}

declare -A _REGION_CACHE=()

account_vpcs_var() {
  local account_key env_key
  account_key="$(safe_name "$1")"
  env_key="$(safe_name "$2")"
  printf 'VPC_IDS_%s_%s' "${account_key}" "${env_key}"
}

aws_for_account() {
  local account="$1"
  shift
  local profile role_arn session_name
  profile="$(account_value "${account}" "PROFILE")"
  role_arn="$(account_value "${account}" "ROLE_ARN")"
  session_name="$(account_value "${account}" "ROLE_SESSION_NAME")"
  [[ -n "${session_name}" ]] || session_name="infraglance-${account}"

  if [[ -n "${role_arn}" ]]; then
    local assume_args=(sts assume-role --role-arn "${role_arn}" --role-session-name "${session_name}" --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)
    if [[ -n "${profile}" ]]; then
      assume_args+=(--profile "${profile}")
    fi

    local creds access_key secret_key session_token
    creds="$(aws "${assume_args[@]}")"
    read -r access_key secret_key session_token <<<"${creds}"
    AWS_ACCESS_KEY_ID="${access_key}" AWS_SECRET_ACCESS_KEY="${secret_key}" AWS_SESSION_TOKEN="${session_token}" aws "$@"
  elif [[ -n "${profile}" ]]; then
    aws --profile "${profile}" "$@"
  else
    aws "$@"
  fi
}

aws_for_publish() {
  if [[ -n "${S3_PROFILE}" ]]; then
    aws --profile "${S3_PROFILE}" "$@"
  else
    aws "$@"
  fi
}

write_vpc_map() {
  : > "${VPC_MAP_FILE}"
  local account label env_name var_name vpc_id

  for account in "${ACCOUNTS[@]}"; do
    label="$(account_label "${account}")"
    for env_name in "${ENVIRONMENTS[@]}"; do
      var_name="$(account_vpcs_var "${account}" "${env_name}")"
      var_exists "${var_name}" || continue
      declare -n vpc_ids="${var_name}"
      for vpc_id in "${vpc_ids[@]}"; do
        printf '%s\t%s\t%s\n' "${label}" "${env_name}" "${vpc_id}" >> "${VPC_MAP_FILE}"
      done
    done
  done
}

validate_account() {
  local account="$1"
  local regions_var
  regions_var="$(account_regions_var "${account}")"
  var_exists "${regions_var}" || die "Missing regions array for account ${account}. Expected ${regions_var}."
  declare -n regions_ref="${regions_var}"
  [[ ${#regions_ref[@]} -gt 0 ]] || die "No regions configured for account ${account}"
}

account_regions() {
  local account="$1"
  local regions_var
  regions_var="$(account_regions_var "${account}")"
  declare -n regions_ref="${regions_var}"

  if [[ "${regions_ref[0]}" == "auto" ]]; then
    if [[ "${PARTITION}" == "aws-us-gov" ]]; then
      partition_regions
    else
      if [[ -z "${_REGION_CACHE[${account}]+x}" ]]; then
        _REGION_CACHE["${account}"]="$(aws_for_account "${account}" ec2 describe-regions --all-regions --query 'Regions[?OptInStatus==`opt-in-not-required` || OptInStatus==`opted-in`].RegionName' --output text | tr '\t' '\n')"
      fi
      printf '%s\n' ${_REGION_CACHE["${account}"]}
    fi
  else
    printf '%s\n' "${regions_ref[@]}"
  fi
}

check_partition_for_account() {
  local account="$1"
  local label arn detected_partition
  label="$(account_label "${account}")"
  arn="$(aws_for_account "${account}" sts get-caller-identity --query Arn --output text)"
  detected_partition="$(printf '%s' "${arn}" | cut -d: -f2)"

  log "Account ${label}: ${arn}"
  if [[ "${PARTITION}" != "auto" && "${detected_partition}" != "${PARTITION}" ]]; then
    die "Account ${label} is in partition ${detected_partition}, but PARTITION=${PARTITION}"
  fi
}

check_config() {
  local account region
  log "Checking InfraGlance config"
  log "Configured partition: ${PARTITION}"
  for account in "${ACCOUNTS[@]}"; do
    validate_account "${account}"
    check_partition_for_account "${account}"
    while IFS= read -r region; do
      [[ -n "${region}" ]] || continue
      log "Account $(account_label "${account}") region: ${region}"
    done < <(account_regions "${account}")
  done
  log "Config check completed"
}

collect_region() {
  local account="$1"
  local label="$2"
  local region="$3"
  local account_dir="$4"
  local vpc_file="${account_dir}/vpc_${region}.json"
  local sg_file="${account_dir}/security_groups_${region}.json"
  local ec2_file="${account_dir}/ec2_${region}.json"
  local rds_file="${account_dir}/rds_${region}.json"
  local reserved_file="${account_dir}/reserved_${region}.json"

  log "Collecting VPCs for ${label} in ${region}"
  aws_for_account "${account}" --region "${region}" ec2 describe-vpcs --output json > "${vpc_file}"
  printf 'vpc\t%s\t%s\t%s\n' "${label}" "${region}" "${vpc_file}" >> "${MANIFEST_FILE}"

  log "Collecting security groups for ${label} in ${region}"
  aws_for_account "${account}" --region "${region}" ec2 describe-security-groups --output json > "${sg_file}"
  printf 'security_group\t%s\t%s\t%s\n' "${label}" "${region}" "${sg_file}" >> "${MANIFEST_FILE}"

  log "Collecting EC2 instances for ${label} in ${region}"
  aws_for_account "${account}" --region "${region}" ec2 describe-instances --output json > "${ec2_file}"
  printf 'ec2\t%s\t%s\t%s\n' "${label}" "${region}" "${ec2_file}" >> "${MANIFEST_FILE}"

  log "Collecting RDS instances for ${label} in ${region}"
  aws_for_account "${account}" --region "${region}" rds describe-db-instances --output json > "${rds_file}"
  printf 'rds\t%s\t%s\t%s\n' "${label}" "${region}" "${rds_file}" >> "${MANIFEST_FILE}"

  log "Collecting EC2 reserved instances for ${label} in ${region}"
  if aws_for_account "${account}" --region "${region}" ec2 describe-reserved-instances --output json > "${reserved_file}"; then
    printf 'reserved\t%s\t%s\t%s\n' "${label}" "${region}" "${reserved_file}" >> "${MANIFEST_FILE}"
  else
    log "Reserved instance collection failed for ${label} in ${region}; continuing"
    rm -f "${reserved_file}"
  fi
}

collect_account() {
  local account="$1"
  local label account_dir region
  validate_account "${account}"
  label="$(account_label "${account}")"
  account_dir="${RUN_DIR}/$(safe_name "${label}")"

  mkdir -p "${account_dir}"
  while IFS= read -r region; do
    [[ -n "${region}" ]] || continue
    collect_region "${account}" "${label}" "${region}" "${account_dir}"
  done < <(account_regions "${account}")
}

render_reports() {
  log "Rendering HTML reports"
  python3 "${SCRIPT_DIR}/render_report.py" \
    --title "${REPORT_TITLE}" \
    --manifest "${MANIFEST_FILE}" \
    --vpcs "${VPC_MAP_FILE}" \
    --output-dir "${OUTPUT_DIR}" \
    --generated-at "${RUN_ID}" \
    --environment-tag-key "${ENVIRONMENT_TAG_KEY}" \
    --auto-discover-vpcs "${AUTO_DISCOVER_VPCS}" \
    --pricing-file "${PRICING_FILE}" \
    --monthly-hours "${MONTHLY_HOURS}" \
    --stopped-amber-days "${STOPPED_AMBER_DAYS}" \
    --stopped-red-days "${STOPPED_RED_DAYS}" \
    --redact-private-ips "${REDACT_PRIVATE_IPS}" \
    --redact-public-ips "${REDACT_PUBLIC_IPS}" \
    --redact-instance-names "${REDACT_INSTANCE_NAMES}" \
    --redact-db-names "${REDACT_DB_NAMES}" \
    --redact-vpc-cidrs "${REDACT_VPC_CIDRS}" \
    --state-file "${OUTPUT_DIR%/}/infraglance-state.json"
}

publish_to_s3() {
  [[ -n "${S3_BUCKET}" ]] || return 0
  [[ -f "${OUTPUT_DIR%/}/index.html" ]] || die "Render produced no output; aborting S3 publish to avoid deleting bucket contents"
  log "Publishing reports to s3://${S3_BUCKET}/${S3_PREFIX}/"
  aws_for_publish s3 sync "${OUTPUT_DIR}/" "s3://${S3_BUCKET}/${S3_PREFIX}/" --delete
  log "Uploading raw data to s3://${S3_BUCKET}/${S3_PREFIX}/raw/${RUN_ID}/"
  aws_for_publish s3 sync "${RUN_DIR}/" "s3://${S3_BUCKET}/${S3_PREFIX}/raw/${RUN_ID}/"
}

main() {
  (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) )) \
    || die "Bash 4.3 or later is required (running ${BASH_VERSION})"
  require_command aws
  require_command python3
  load_config

  if [[ "${COMMAND}" == "check" ]]; then
    check_config
    exit 0
  fi

  RUN_ID="$(date '+%Y-%m-%d-%H-%M-%S')"
  RUN_DIR="${WORK_DIR%/}/${RUN_ID}"
  MANIFEST_FILE="${RUN_DIR}/manifest.tsv"
  VPC_MAP_FILE="${RUN_DIR}/vpcs.tsv"

  mkdir -p "${RUN_DIR}" "${OUTPUT_DIR}"
  : > "${MANIFEST_FILE}"
  write_vpc_map

  local account
  for account in "${ACCOUNTS[@]}"; do
    collect_account "${account}"
  done

  render_reports
  publish_to_s3
  log "Done. Open ${OUTPUT_DIR%/}/index.html"
}

main "$@"
