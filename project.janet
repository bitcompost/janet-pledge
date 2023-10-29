(declare-project
  :name "janet-pledge"
  :license "ISC"
  :url "https://github.com/bitcompost/janet-pledge"
  :repo "git+https://github.com/bitcompost/janet-pledge.git")

(declare-native
  :name "pledge"
  :source ["main.c" "landlock.c" "pledge.c" "unveil.c"])
