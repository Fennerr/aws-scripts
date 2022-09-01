#!/usr/bin/env fish
argparse 's/serial=' 'c/code=' 'h/help' 'r/region=' 'p/profile=' 'a/awspx' 'l/local-scope' -- $argv

function print_help
    echo "mfa-cli.sh [-h|--help] -s|--serial MFA-ARN -c|--code MFA-CODE [-r|--region DEFAULT-REGION] [-p|--profile PROFILE-NAME] [-a|--awspx] [-l|--local-scope]"
    echo "Example: /media/sf_VMShare/AWS/scripts/mfa-cli.sh -s arn:aws:iam::123456789012:mfa/mwr_cybersec_temp -p example_profile -r eu-west-1 -c 497282"
end


if set -q _flag_help
    print_help
    return 0
end

if not set -q _flag_c; or not set -q _flag_s
    echo 'Script requires both the serial device ARN and MFA code'
    print_help
    return 0
end

if set -q _flag_r
    if set -q _flag_l
        set -gx AWS_DEFAULT_REGION $_flag_r
    else
        set -Ux AWS_DEFAULT_REGION $_flag_r
    end
end

if set -q _flag_p
    set output (aws sts get-session-token --serial-number $_flag_s --token-code $_flag_c --profile $_flag_p)
else
    set output (aws sts get-session-token --serial-number $_flag_s --token-code $_flag_c)
end

# echo $output | jq

if set -q _flag_l
    # Set the global variables, which will take precidence over the universal variables for the current tab
    set -gx AWS_ACCESS_KEY_ID (echo $output | jq -r '.Credentials.AccessKeyId')
    set -gx AWS_SECRET_ACCESS_KEY (echo $output | jq -r '.Credentials.SecretAccessKey')
    set -gx AWS_SESSION_TOKEN (echo $output | jq -r '.Credentials.SessionToken')
else
    # Clear the variables, incase there were global variables set, which would take precidence over the universal variables
    set -e AWS_ACCESS_KEY_ID
    set -e AWS_SECRET_ACCESS_KEY
    set -e AWS_SESSION_TOKEN
    # Set the universal variables
    set -Ux AWS_ACCESS_KEY_ID (echo $output | jq -r '.Credentials.AccessKeyId')
    set -Ux AWS_SECRET_ACCESS_KEY (echo $output | jq -r '.Credentials.SecretAccessKey')
    set -Ux AWS_SESSION_TOKEN (echo $output | jq -r '.Credentials.SessionToken')
end

if set -q _flag_a
    # Copy the creds to the awspx container
    set creds_file_content (printf "[default]\\\\naws_access_key_id=%s\\\\naws_secret_access_key=%s\\\\naws_session_token=%s" $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY $AWS_SESSION_TOKEN)
    echo -e "echo '"$creds_file_content"' > ~/.aws/credentials" | docker exec -i awspx /bin/bash -
    if set -q _flag_r
        set config_file_content (printf "[default]\\\\nregion = %s" $_flag_r)
        echo -e "echo '"$config_file_content"' > ~/.aws/config" | docker exec -i awspx /bin/bash -
    end
end


echo "Commands to set the environment variables again (if they get overwritten/erased and you want to reset them):"
echo '------------------------------------'
if set -q _flag_r
    printf "set -Ux AWS_ACCESS_KEY_ID \"%s\"\nset -Ux AWS_SECRET_ACCESS_KEY \"%s\"\nset -Ux AWS_SESSION_TOKEN \"%s\"\nset -Ux AWS_DEFAULT_REGION \"%s\"" $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY $AWS_SESSION_TOKEN $_flag_r | tee $HOME/.token_file
else
    printf "set -Ux AWS_ACCESS_KEY_ID \"%s\"\nset -Ux AWS_SECRET_ACCESS_KEY \"%s\"\nset -Ux AWS_SESSION_TOKEN \"%s\"" $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY $AWS_SESSION_TOKEN | tee $HOME/.temp_token_file
end
# Add some blank space to make it look better
echo ' '
echo ' '
echo ' '
echo "Contents to copy paste into the credentials file (if you would like to use a profile rather than environment variables):"
echo '------------------------------------'
#echo $output | awk '{printf("export AWS_ACCESS_KEY_ID=\"%s\"\nexport AWS_SECRET_ACCESS_KEY=\"%s\"\nexport AWS_SESSION_TOKEN=\"%s\"\nexport AWS_SECURITY_TOKEN=\"%s\"\n",$2,$4,$5,$5)}' | tee $HOME/.token_file
echo $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY $AWS_SESSION_TOKEN | awk '{printf("AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_SESSION_TOKEN=%s",$1,$2,$3)}' | tee $HOME/.temp_aws_credentials
echo ' '
