apache2_install 'default_install'
apache2_module 'headers'
apache2_module 'proxy'
apache2_module 'proxy_http'
apache2_module 'rewrite'
apache2_module 'ssl'

# TODO: Remove this work-around once a fix makes it into apache2 cookbook.
# See: https://github.com/svanzoest-cookbooks/apache2/issues/398
service 'apache2' do
  extend Apache2::Cookbook::Helpers
  service_name lazy { apache_platform_service_name }
  supports restart: true, status: true, reload: true
  action :nothing
end

apache2_default_site['jira']['apache2']['virtual_host_alias'] do
  cookbook node['jira']['apache2']['template_cookbook']
end
