#!/bin/sh
set -eu

knowledge_dir="${SENTINEL_KNOWLEDGE_DIR:-knowledge-data}"
mkdir -p "$knowledge_dir"

clone_or_update() {
	name="$1"
	url="$2"
	destination="$knowledge_dir/$name"
	if [ -e "$destination" ] && [ ! -d "$destination/.git" ]; then
		echo "Refusing to overwrite non-git path: $destination" >&2
		exit 1
	fi
	if [ ! -d "$destination/.git" ]; then
		git clone --depth 1 "$url" "$destination"
	else
		git -C "$destination" pull --ff-only
	fi
}

seclists_dir="$knowledge_dir/SecLists"
if [ -e "$seclists_dir" ] && [ ! -d "$seclists_dir/.git" ]; then
	echo "Refusing to overwrite non-git path: $seclists_dir" >&2
	exit 1
fi
if [ ! -d "$seclists_dir/.git" ]; then
	git clone --depth 1 --filter=blob:none --sparse \
		https://github.com/danielmiessler/SecLists.git "$seclists_dir"
else
	git -C "$seclists_dir" pull --ff-only
fi
git -C "$seclists_dir" sparse-checkout set \
	Discovery Fuzzing Passwords Usernames Pattern-Matching Ai/LLM_Testing

clone_or_update HUNT https://github.com/bugcrowd/HUNT.git
clone_or_update Arcanum-PI-Taxonomy https://github.com/Arcanum-Sec/arc_pi_taxonomy.git

echo "Knowledge sources are ready under $knowledge_dir"
