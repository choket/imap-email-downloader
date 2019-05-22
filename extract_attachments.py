import email
import os

for root, dir, files in os.walk("A:\email_dumps"):
	for file in files:
		if file.endswith(".eml"):
			file_path = os.path.join(root, file)

			with open(file_path, errors="ignore", encoding="utf-8") as f:
				email_message = email.message_from_file(f)

				for attachment in email_message.get_payload()[1:]:
					if isinstance(attachment, str):
						# Message doesn't have attachments
						continue

					print("Extracting attachments of {}".format(file_path))

					attachment_type = attachment.get_content_type()
					if attachment_type.startswith("image/"):
						attachment_contents = attachment.get_payload(decode=True)
						attachment_filename = attachment.get_filename()

						if attachment_filename is None:
							continue

						if attachment_filename.startswith("=?"):
							continue

						for char in (">", "<", ":", "\"", "/", "\\", "|", "?", "*"):
							if char in attachment_filename:
								attachment_filename = attachment_filename.replace(char, "_")

						email_number = file.split("-")[0].zfill(4)

						output_directory = root.replace("A:\\email_dumps", "A:\\email_attachments")

						os.makedirs(output_directory, exist_ok=True)

						output_filepath = os.path.join(output_directory, email_number + "-" + attachment_filename)

						try:
							with open(output_filepath, "wb") as a:
								a.write(attachment_contents)
						except Exception as e:
							with open("A:\\email_attachments\\error_log.txt", "w") as log:
								log.write(str(e) + "\n")
