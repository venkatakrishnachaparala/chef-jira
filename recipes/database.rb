settings = merge_jira_settings

database_connection = {
  :host => settings['database']['host'],
  :port => settings['database']['port']
}

case settings['database']['type']
when 'mysql'
  mysql2_chef_gem 'jira' do
    client_version settings['database']['version'] if settings['database']['version']
    action :install
  end

  mysql_service 'jira' do
    version settings['database']['version'] if settings['database']['version']
    bind_address settings['database']['host']
    port settings['database']['port'].to_s
    initial_root_password node['mysql']['server_root_password']
    data_dir node['mysql']['data_dir'] if node['mysql']['data_dir']
    action [:create, :start]
  end

  database_connection[:username] = 'root'
  database_connection[:password] = node['mysql']['server_root_password']

  mysql_database settings['database']['name'] do
    connection database_connection
    # See: https://confluence.atlassian.com/display/JIRAKB/Health+Check%3A+Database+Collation
    collation 'utf8_bin'
    encoding 'utf8'
    action :create
  end

  # See this MySQL bug: http://bugs.mysql.com/bug.php?id=31061
  mysql_database_user '' do
    connection database_connection
    host 'localhost'
    action :drop
  end

  mysql_database_user settings['database']['user'] do
    connection database_connection
    host '%'
    password settings['database']['password']
    database_name settings['database']['name']
    action [:create, :grant]
  end
when 'postgresql'
  database_connection[:username] = 'postgres'
  database_connection[:password] = 'changeit'
  
  postgresql_server_install 'My PostgreSQL Server install' do
  version settings['database']['version']
  action :install
end

  postgresql_user settings['database']['user'] do
      password settings['database']['password']
      end

  postgresql_database settings['database']['name'] do
    # See: https://confluence.atlassian.com/display/JIRAKB/Health+Check%3A+Database+Collation
    encoding 'utf8'
    template 'template0'
    owner settings['database']['user']
end
end
