# app.rb
require 'sinatra'
require 'cgi'

set :bind, '0.0.0.0'
set :port, 4567

REPO_PATH = ENV['REPO_PATH'] || "../linjector/"  # TODO: change this

# Super simple “sanitizer” for path-like inputs
def sanitize_path(path)
  path = path.to_s
  # strip leading/trailing whitespace
  path = path.strip
  # remove dangerous characters
  path = path.gsub(/[;&|`$><!]/, '')
  # normalize away ".." segments
  parts = path.split('/').reject { |p| p.empty? || p == '.' || p == '..' }
  File.join(*parts)
end

helpers do
  def h(str)
    CGI.escapeHTML(str.to_s)
  end
end

get '/' do
  # List tracked files
  files = `cd #{REPO_PATH} && git ls-files`.split("\n")
  erb :index, locals: { files: files }
end

def binary?(string)
  # crude heuristic: lots of non-text bytes
  string.each_byte.take(1024).any? { |b| b == 0 } ||
    (string.each_byte.take(1024).count { |b| b < 9 || (b > 13 && b < 32) } > 0)
end

get '/file/*' do
  requested = params[:splat].first
  decoded   = CGI.unescape(requested)          # turns %20 into space [web:82]
  safe_rel  = sanitize_path(decoded)

  content = `cd #{REPO_PATH} && git show HEAD:"#{safe_rel}" 2>/dev/null`
  halt 404, "File not found: #{ REPO_PATH }#{ safe_rel }" if content.empty?

  if binary?(content)
    tmp = Tempfile.new('gitfab')
    tmp.binmode
    tmp.write(content)
    tmp.flush

    mime = Rack::Mime.mime_type(File.extname(safe_rel), 'application/octet-stream')
    # send_file will close the tempfile when done if you unlink after
    send_file tmp.path,
              disposition: 'attachment',
              filename: File.basename(safe_rel),
              type: mime
  else
    erb :file, locals: { path: safe_rel, content: content }
  end
end

get '/history/*' do
  requested = params[:splat].first
  decoded   = CGI.unescape(requested)          # same fix here [web:82]
  safe_rel  = sanitize_path(decoded)

  log = `cd #{REPO_PATH} && git log --pretty=format:"%h|%an|%ad|%s" -- "#{safe_rel}" 2>/dev/null`
  halt 404, "No history for this file: #{ REPO_PATH }#{ safe_rel }" if log.empty?

  entries = log.split("\n").map do |line|
    sha, author, date, subject = line.split('|', 4)
    { sha: sha, author: author, date: date, subject: subject }
  end

  erb :history, locals: { path: safe_rel, entries: entries }
end

