import boto3
import os
import pathlib
s = boto3.session.Session(profile_name='sanlam-dev-admin')

def sync_s3_to_local(bucket_name):
    output_dir = pathlib.Path(__file__).parent.absolute() / 's3-buckets-output' / bucket_name
    output_dir.mkdir(parents=True, exist_ok=True)

    files = set(os.listdir(output_dir))

    s3 = s.resource('s3')
    bucket = s3.Bucket(bucket_name)
    for obj in bucket.objects.all():
        filename = obj.key
        if filename[-1] == '/':
            # This is a folder, skip
            continue
        if filename not in files:
            try:
                if len(filename.split('/')) > 1:
                    # Need to create nested directories
                    nested_output_dir = output_dir  / '/'.join(filename.split('/')[:-1])
                    nested_output_dir.mkdir(parents=True, exist_ok=True)
                    base_filename = filename.split('/')[-1]
                    print(f"Downloading {filename} to {str(nested_output_dir / base_filename)}")
                    bucket.download_file(filename, str(nested_output_dir / base_filename))
                else:
                    print(f"Downloading {filename} to {str(output_dir / filename)}")
                    bucket.download_file(filename, str(output_dir / filename))
            except:
                catchme = True


s3 = s.client("s3")
bucket_names = [x['Name'] for x in s3.list_buckets()['Buckets']]

for bucket_name in bucket_names:
    sync_s3_to_local(bucket_name=bucket_name)