# Jira module
module Jira
  # Jira::Helpers module
  # rubocop:disable Metrics/ModuleLength
  module Helpers
    # Merges JIRA settings from data bag and node attributes.
    # Data dag settings always has a higher priority.
    #
    # @return [Hash] Settings hash
    def merge_jira_settings
      @settings_from_data_bag ||= settings_from_data_bag
      settings = Chef::Mixin::DeepMerge.deep_merge(
        @settings_from_data_bag,
        node['jira'].to_hash
      )

      case settings['database']['type']
      when 'mysql'
        settings['database']['port'] ||= 3306
      when 'postgresql'
        settings['database']['port'] ||= 5432
      when 'oracle'
        settings['database']['port'] ||= 1521
      else
        warn 'Unsupported database type! - Use a supported type or handle DB creation/config in a wrapper cookbook!'
      end

      settings
    end

    # Fetchs Confluence settings from the data bag
    #
    # @return [Hash] Settings hash
    def settings_from_data_bag
      begin
        bag = node['jira']['data_bag_name']
        item = node['jira']['data_bag_item']
        result = data_bag_item(bag, item)['jira']
        return result if result.is_a?(Hash)
      rescue
        Chef::Log.info("Couldn't load data bag item #{bag}/#{item}")
      end
      {}
    end

    # Detects the current JIRA version.
    # Returns nil if JIRA isn't installed.
    #
    # @return [String] JIRA version
    def jira_version
      pom_file = File.join(
        node['jira']['install_path'],
        '/atlassian-jira/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.properties'
      )

      begin
        return Regexp.last_match(1) if File.read(pom_file) =~ /^version=(.*)$/
      rescue Errno::ENOENT
        # JIRA is not installed
        return nil
      end
    end

    # Returns download URL for JIRA artifact
    # rubocop:disable Metrics/AbcSize
    # rubocop:disable Metrics/PerceivedComplexity
    # rubocop:disable CyclomaticComplexity
    def jira_artifact_url
      return node['jira']['url'] unless node['jira']['url'].nil?

      base_url = 'https://www.atlassian.com/software/jira/downloads/binary'
      version  = node['jira']['version']
      product = "#{base_url}/atlassian-jira-#{node['jira']['flavor']}-#{version}"

      # JIRA versions >= 7.0.0 have different flavors
      # By default we assume you want >= 7.0.0
      v = Gem::Version.new(version)

      if node['jira']['flavor'].downcase == 'software' && (v >= Gem::Version.new('7.0.0'))
        # Software had a different set of URLs for from 7.0.0 to 7.1.7
        if v < Gem::Version.new('7.1.9')
          product = "#{base_url}/atlassian-jira-#{node['jira']['flavor']}-#{version}-jira-#{version}"
        elsif v >= Gem::Version.new('7.2')
          product = "#{base_url}/atlassian-jira-#{node['jira']['flavor']}-#{version}"
        end
      elsif v < Gem::Version.new(7)
        product = "#{base_url}/atlassian-jira-#{version}"
      end

      # Return actual URL
      case node['jira']['install_type']
      when 'installer'
        "#{product}-#{jira_arch}.bin"
      when 'standalone'
        "#{product}.tar.gz"
      else
        fail 'Only the "installer" or "standalone" install types are supported by Atlassian and this cookbook.'
      end
    end
    # rubocop:enable CyclomaticComplexity
    # rubocop:enable Metrics/PerceivedComplexity
    # rubocop:enable Metrics/AbcSize

    # Returns SHA256 checksum of specific JIRA artifact
    # rubocop:disable Metrics/AbcSize
    def jira_artifact_checksum
      return node['jira']['checksum'] unless node['jira']['checksum'].nil?

      version = node['jira']['version']
      flavor  = node['jira']['flavor']

      if Gem::Version.new(version) < Gem::Version.new(7)
        sums = jira_checksum_map[version]
      else
        versionsums = jira_checksum_map[version]
        sums = versionsums[flavor]
      end

      warn "JIRA version #{version} is not supported by the cookbook. Set node['jira']['checksum'] = false to disable checksum checking." unless sums

      case node['jira']['install_type']
      when 'installer' then sums[jira_arch]
      when 'standalone' then sums['tar']
      end
    end
    # rubocop:enable Metrics/AbcSize

    def jira_arch
      (node['kernel']['machine'] == 'x86_64') ? 'x64' : 'x32'
    end

    # rubocop:disable Metrics/MethodLength
    # Returns SHA256 checksum map for JIRA artifacts
    def jira_checksum_map
      {
        '5.2.11' => {
          'x32' => '7088a7d123e263c96ff731d61512c62aef4702fe92ad91432dc060bab5097cb7',
          'x64' => 'ad4a851e7dedd6caf3ab587c34155c3ea68f8e6b878b75a3624662422966dff4',
          'tar' => '8d18b1da9487c1502efafacc441ad9a9dc55219a2838a1f02800b8a9a9b3d194'
        },
        '6.0.8' => {
          'x32' => 'ad1d17007314cf43d123c2c9c835e03c25cd8809491a466ff3425d1922d44dc0',
          'x64' => 'b7d14d74247272056316ae89d5496057b4192fb3c2b78d3aab091b7ba59ca7aa',
          'tar' => '2ca0eb656a348c43b7b9e84f7029a7e0eed27eea9001f34b89bbda492a101cb6'
        },
        '6.1' => {
          'x32' => 'c879e0c4ba5f508b4df0deb7e8f9baf3b39db5d7373eac3b20076c6f6ead6e84',
          'x64' => '72e49cc770cc2a1078dd60ad11329508d6815582424d16836efd873f3957e2c8',
          'tar' => 'e63821f059915074ff866993eb5c2f452d24a0a2d3cf0dccea60810c8b3063a0'
        },
        '6.1.5' => {
          'x32' => 'f3e589fa34182195902dcb724d82776005a975df55406b4bd5864613ca325d97',
          'x64' => 'b0b67b77c6c1d96f4225ab3c22f31496f356491538db1ee143eca0a58de07f78',
          'tar' => '6e72f3820b279ec539e5c12ebabed13bb239f49ba38bb2e70a40d36cb2a7d68f'
        },
        '6.3.15' => {
          'x32' => '739ac3864951b06a4ce910826f5175523b4ab9eae5005770cbcb774cc94e2e29',
          'x64' => 'a334865dd0b5df5b3bcc506b5c40ab7b65700e310edb6e7e6f86d30c3a8e3375',
          'tar' => '056553ec88cdeeefec73a6692d270a21b9b395af63a5c1ad9865752928dcec2c'
        },
        '6.4.6' => {
          'x32' => 'bede3c18bced84a4b2134ad07c5c4387f6c6991cfaf59768307a31bf72ba8de4',
          'x64' => '0ea1cc37b7de135315b2b241992fca572f808337b730ad68dc0c8c514136a480',
          'tar' => '9bfdba6975cc5188053efe07787d290c12347b62ae13a10d37dd44f14fe68e05'
        },
        '6.4.7' => {
          'x32' => '8545173ce7c0abdad2213a9514adc2b91443acbed31de1a47a385e52521f7114',
          'x64' => '95db7901de1f0c3d346b6ce716cbdf8cd7dc8333024c26b4620be78ba70f3212',
          'tar' => 'c8623ca2a1c0fea18e3921ee1834b3ffe39d70ee2c539f99a99eee2cfb09edd4'
        },
        '6.4.11' => {
          'x32' => 'c68ac38ff0495084dd74d73a85c5e37889af265f3097149a05e4752279610ad6',
          'x64' => '4030010efd5fbec3735dc3a585cd833af957cf7efe4f4bbc34b17175ff9ba328',
          'tar' => 'a8fb59ea41a65e751888491e4c8c26f8a0a6df053805a1308e2b6711980881ec'
        },
        '6.4.12' => {
          'x32' => 'dc807ebed5065416eebb117c061aa57bd07c1d168136aca786ae2b0c100f7e30',
          'x64' => '9897ae190a87a61624d5a307c428e8f4c86ac9ff03e1a89dbfb2da5f6d3b0dbd',
          'tar' => 'a77cf4c646d3f49d3823a5739daea0827adad1254dae1d1677c629e512a7afd4'
        },
        '7.0.0' => {
          'core' => {
            'x32' => 'bcd4746dcd574532061f79ec549e16d8641346f4e45f1cd3db032730fd23ea80',
            'x64' => '314bb496b7d20fb1101eb303c48a80041775e4fadd692fd97583b9c248df5099',
            'tar' => '56bdae7b78ac4472e6c9a22053e4b083d9feb07ee948f4e38c795591d9fc9ae9'
          },
          'software' => {
            'x32' => '3a43274bc2ae404ea8d8c2b50dcb00cc843d03140c5eb11de558b3025202a791',
            'x64' => '49e12b2ba9f1eaa4ed18e0a00277ea7be19ffd6c55d4a692da3e848310815421',
            'tar' => '2eb0aff3e71272dc0fd3d9d6894f219f92033d004e46b25b542241151a732817'
          }
        },
        '7.0.2' => {
          'core' => {
            'x32' => '483cbe3738c5b556ddbadf11adaf98428b0d6d7aec2460eba639c8f4190a6df6',
            'x64' => 'cda659e4b15eb6c70b2ad81acb2917ab66f6a6b114e8f3dad69683ec21b3a844',
            'tar' => '5568de1e67cbfe6c1d3e28869988c78fdc632c59774908d4e229aab1439d255f'
          },
          'software' => {
            'x32' => '235cd2466e3b1e3ac2f4826ee37d64cf53af3c49d72a816a380979931b9fb5fd',
            'x64' => '8ebd0609b3520dfa399672dd10556cbe4886aeb8c59dbf11058b61d5eedb5e2f',
            'tar' => '49a4aca54a5461762d5064b27fce9cb2b8a8a020c1c073c7499a48c19cc8542b'
          }
        },
        '7.0.4' => {
          'core' => {
            'x32' => '5d4fdf75e9f8d17e8e451fa07e8aee9160c2b1a57c563cbedf95b0c40d8b44d0',
            'x64' => '002b83c2a1b1b962c722eefd326797f969a0ffdeb936414efad35ab7836aa8ce',
            'tar' => '915ab38389cfc7777afd272683ce8c8226ccab5e8cc672352e5de14eb99d748c'
          },
          'software' => {
            'x32' => '24cf62ddab600d9ec989693c8f48f1581fcf65e5a25dfc8b5bb6d2de0d3beaa3',
            'x64' => 'bbddc723ab999a948cc9ebd2d4ccdc216e127805b2869cc66614bd4249141134',
            'tar' => '234f66679425c2285a68d75c877785d186cc7b532d73ada0d6907d67833e1522'
          }
        },
        '7.0.10' => {
          'core' => {
            'x32' => '8687f938df213ccd267bca936fc9c213bc01f58d03a4ebb67fbfd3859a92bb7a',
            'x64' => 'edef201ee8e8b58a5cb86728ab3411d3bee8af34b13b5844dcf543f079ebeb19',
            'tar' => 'f0a5c8fb0574f3037088e4449e0b3c5d996331d658b3bead8bf7df465df17c74'
          },
          'software' => {
            'x32' => '362c568471feffc80042b120cdb8b670d5d6a680822a05927fe6d061eda07a11',
            'x64' => '55b4e6314983602fb518b49caeb5f77c4b4b3bd8313bf0c685e3be0152a8f035',
            'tar' => '64af0960961ffcb8a03164dd473ada297c83635dca54ce5b16b1117aa0823cb7'
          }
        },
        '7.1.0' => {
          'core' => {
            'x32' => '1ac8dc90ec6a311363f04f185333f7e38f3b3e2a22d71fe4c1cf9a32a445c502',
            'x64' => '2c81a5163280c7533fafec6cf3954b8c1be6c0e0f9e394aadaa10bc6a7307170',
            'tar' => '5b07753a4cf000337cc8103aeb30ed51683df80765a0b0f1db5afe3eefc103d5'
          },
          'software' => {
            'x32' => 'd0e51e274e964e2f349c69c9fbf7d37f9e69353f653f0a3f8f6c731ee007bbd8',
            'x64' => '7f0fda48b280eaabd256a0d77a991c1fb7b654acb309e10ee64ecabf83a8dd09',
            'tar' => 'a4bdd2c0d9fd92c1cebab6eacef29e35f73058350a918bdfcb1b6a991d9992f2'
          }
        },
        '7.1.2' => {
          'core' => {
            'x32' => '446005c42051124a4c2aa9fc00cec79d9733054b9fd5a4945af4b4b152ba88d3',
            'x64' => 'efc187703a90ced1c31273f1da9fb1e4282a2a9f100e2d4bbe7ba88fc31cdeeb',
            'tar' => 'a402c1d97ad408f9ba3256dcddde9f7c50c013165f5c3ccede87538cb9d818fb'
          },
          'software' => {
            'x32' => 'c33d24f724500f086c1d2c3682f3371f71dfb6e99e6d1d7f2e12a5c6c56973a0',
            'x64' => 'f72337b8d55468c2b3f0526e7496d03dd1ec9bb3d482d0269fcf87f48791094a',
            'tar' => '4837de0425845966a4138e518da5325436bbc6c91bc78e7497bfc0384dfa411b'
          }
        },
        '7.1.7' => {
          'core' => {
            'x32' => 'e2b590c43b23f514b05cd27a37bc97bbaef9bb60098dca8c4f742c07afa12154',
            'x64' => 'c61c2e9f208867bee6db1d82c34f6248b6f220058459e6e13c6c24b8ca80528c',
            'tar' => '61f1def45e069a085922e24a647447709f19d3a520993c0f8f5583f4f9c5b178'
          },
          'software' => {
            'x32' => '57035f4c826abf352e3ef60431602a8753cc58fe98b35f6fa72db940f6e28c78',
            'x64' => '08f49dcfec3b0764a21d318363c2a72780c52c3e95823ade0bab233dcc36f638',
            'tar' => '2cb08d754072293a23906d7db7ec4bce09a53d783e27145e416f63fd205e59c1'
          }
        },
        '7.1.9' => {
          'core' => {
            'x32' => '3166c2f10b3193821b221042784985b5081de935a3fb0630e9d6dac437469d7d',
            'x64' => '5617b87790c6d0413047e3cc7e3ad041fb410da91101c49fb759163ba2c6e998',
            'tar' => '2cf04f25edbe19e7b6d9e7320c78af107424c7eb5e81f6cbbb69802623b695a2'
          },
          'software' => {
            'x32' => '98d41db73b342c95a08fec233ddfb5da928875366e1cfea941be7f95bf0cf126',
            'x64' => '02d5d3adecc4d218ff258ad69ac39390678434359638d1785e78562178f39408',
            'tar' => 'f03f2a8dd42c4b5f03918b326f14d7339f16f60fee0fa4a4d9c2e04c82dbbed2'
          }
        },
        '7.1.10' => {
          'core' => {
            'x32' => '530f253a6fa2b4d0e4ec8b02a4c546deeba21e881c8735008640dcaa38958d5d',
            'x64' => 'deb3ca344a9caba48b444c9dbe7529245c329bfffaaa211bdc52abc9aa4df0ec',
            'tar' => '234de0845500ede5af654ad2b88ed69ac57aa966c3a5f418b5702ca0508aec44'
          },
          'software' => {
            'x32' => 'a18fddcbc087294b44c6f0da3cd5cfe53aaa8caf7aa74fa30f2aa8ca2ebff58a',
            'x64' => 'fac63007aaced032ca47855966981ae2808fb2a8e3519e4cdbc799a3341debe0',
            'tar' => 'd13bd5c8768cc19844f64f6e1e5ae754c2601a955b5a95e1e4ef55e864619a21'
          }
        },
        '7.2.0' => {
          'core' => {
            'x32' => 'c3a02583c7498d9fcf6dd92e73b2e0390ef2a0ff03edb5e1396fae3c23bd2d51',
            'x64' => '42a7ee7379c46d6cbdda498b0a702a000f2806f2153ac132f1645bfe2f39e576',
            'tar' => '20f376cabd4565d37543f39168c553b717645521b947dc14af85a87a5d6db403'
          },
          'software' => {
            'x32' => 'e6f3369c4ad2788a82e5ca73762076a66c8de149b4e8a8ca14d95e3721f6304b',
            'x64' => 'ba23f268aff987d6110406dc0d2fa4658c6584db7586755f4fa30cb1a01ae43f',
            'tar' => 'aef51677548089f9f85e78eefd80bd21af5464a18985e1c071218f921a4f1f10'
          }
        },
        '7.2.1' => {
          'core' => {
            'x32' => '0fe47f6f532994fc7a6a8a75a0c03fe47eeb233c68e8996296500f8e770b5b2c',
            'x64' => '0e1462185b06439edb1c86060214dbcba076dc11142cf3c50ae3ee9acfa53f4a',
            'tar' => '5ee23a97049080e1379a038635d719f0c694de6fa35aa945d87783f683ba9a6d'
          },
          'software' => {
            'x32' => 'dd6303d52b5be18dcd89423cde5f9be468845036769553c5a1ec0d22517ff188',
            'x64' => 'b41c0c567a3e203d3e1ade7dbddf2a692dffa9d8629f88281509595665846111',
            'tar' => '16279d1d3e6cb7fb1bdf74d18fac8467746b72d4164036d19e2955a7332b8cb3'
          }
        },
        '7.2.2' => {
          'core' => {
            'x32' => '2cf576a725f5e730ee14028bf61a12d320e1886e5e3beff4869d8e73c2f75dbc',
            'x64' => '7ab345fb4eb5932c768008c0d15b523f10732774e595d073fd737c410afff3ca',
            'tar' => '40f923d73abc3cf96c115a8aa6627065cc6c8df946ada226dde80dcfc379904a'
          },
          'software' => {
            'x32' => 'f7e04a8e0ecd593c7a6b04cb5f6c0a6094092f3f17974d96edb9d829c2492f30',
            'x64' => '8de4607beb9cdcf71b3be7e1cb7c3d1e0c0dd716c0eb79c8b33e299338b5fc6d',
            'tar' => 'f6a7c72b11e47c4225e71b22531d54279f23a7cbb02671e5d8747c26a98f3d63'
          }
        },
        '7.2.3' => {
          'core' => {
            'x32' => '38a6064a63933aecf09b131d70e2c982f55a690b95a2ed3e69b51f00b474940b',
            'x64' => '39c0a43a62be0a3daba06e66b8c110202815ec8460d437e0a8c4b65df9b966e8',
            'tar' => '13ae134a4ddeed32b4a08a520c2ec8d410e9e93c4d5657d808b10ac9f83483d2'
          },
          'software' => {
            'x32' => '9d3a0413b32c07ffbfb717efb07d8bde28d9dfdac7cd24396bb6b151757e40d2',
            'x64' => 'e0d02381d951a0f745c3e1e77e673932d504c90db757f0caa9cd22ab13a6d910',
            'tar' => 'c9c310fdf4702403f119b804907be8143366b7a9d71d0e28356fe4287a706708'
          }
        },
        '7.2.4' => {
          'core' => {
            'x32' => '4b21768c1a04eb6c46fb29b50491c0c50bfbaee0f37d8bb849131fe1264d2140',
            'x64' => 'b7428584ea394855686a5e5fdb7bc1f636dd2ad133c8a4de39ba6b06c77edd34',
            'tar' => 'c5927ef75eec40b61e59b0fe4139ef0a2e38765d611cd8458c7b478060eeef52'
          },
          'software' => {
            'x32' => '785052efba8d410fba9d694e94e453879a56643ecd7bdbc299e813a8160f2555',
            'x64' => '4221c95932f4fa14394526a2ae03e4424f8a0e86979b7c92a8e8c4a020801521',
            'tar' => '0a57714dc5cf8d136a5ecf9156c6875f5547ce6c2b7aac9acc94695ea2d4b529'
          }
        },
        # 7.2.5 Cancelled
        '7.2.6' => {
          'core' => {
            'x32' => 'd3f9c7bdcc6cf0bd9c68f654b12d1d65e2d45b69e71868c219c300571adcc5ca',
            'x64' => 'e6afc6aed46b85ee799fd077bf94c2fc7e70ae5d2630580e630aaf97c4cc8d48',
            'tar' => '4136ffa64c44c84dca33032b1f0fc05b2316fa6beb54cddf0b922084378908e3'
          },
          'software' => {
            'x32' => 'b37882cdadbc98a19bdb833c68a6ee95c8de58d39cf1e14189888b034c676a08',
            'x64' => 'fb8e1a17f17676373c99bb00df717a148e69897106a66d6f4be3cabfd9af4626',
            'tar' => '9369a8ce67ff200aa098a14690fd65a023f6ea7c5dbddf300462456cd35bea84'
          }
        },
        '7.2.7' => {
          'core' => {
            'x32' => '89759f647b1bd2ebb77915e0dd52609f3adf3ce5af911ceb37fb66a0b9555956',
            'x64' => '01d8a4edf45817aeff6bee3ec750c6b365bc009dffa3df56f300558b0e433c37',
            'tar' => 'e27f2d6979beea214775e024989e6ab8de0184d47bda49be076c7b54da1b37e3'
          },
          'software' => {
            'x32' => '16faa31f87bb876bb856bdace1cca3c5d4f4e25a49cc96a9b8c5ffc5953f59a2',
            'x64' => '2564e47e924155f417706eafacdd089c69c1dfeab03a480946aeb41e8867b58e',
            'tar' => '40c675eb1f35ca8003c3dfd952d9283bc2a69591bc641f3b40f44acacd02916c'
          }
        },
        '7.2.8' => {
          'core' => {
            'x32' => '23eddc46caa36d53945fc01e668e3a7dcbc26b9e9c938a77d1a4eff74e600d00',
            'x64' => '2b79736d90343a24d29d2162d46ac321722d94aed8ada399b6ab2b7df510d1a0',
            'tar' => '8e6eb7f7675f6c2573e57a0fee9eb1c9a97991f2e12eadc0b0a3c5da223a2f7a'
          },
          'software' => {
            'x32' => '005bf5ef4a15c83d15d944986293aa72fad5b0a12f9167184c5601a6104a7907',
            'x64' => '38a344396406b53567649a007852dafb0aab2da2fab23363f25d247be56fad31',
            'tar' => '4a2fd397f54fd00dc06ba1a8537666fff9eab6700b1dd9e4668189d6d8cc2784'
          }
        },
        '7.2.9' => {
          'core' => {
            'x32' => '4fef08dbdbbc89bc209dac5dc3f01d79b96a5291816dc79d032b178885eaa7b3',
            'x64' => '4cae2d84c5b40e23fefcb7ced905a148ac71cbe5e01eee3bdc90c24986aeba09',
            'tar' => '06b6e89c8926355b83dc635148e90fa04f8655677ed357f0ad30df16bb399c3e'
          },
          'software' => {
            'x32' => 'fcd11487d4924c6f815519b7cbf8b2a9e40a1916c6a7361696fdf73f997e2051',
            'x64' => '0643dfd1b0923c9cb337f0d596fff2e08f34c553ae389657f4308f176fcce468',
            'tar' => '03b16edb9489b9f5fde4017632ebbc9eab38a469e84c10ee2e7a7d34895ebcea'
          }
        },
        '7.3.0' => {
          'core' => {
            'x32' => '4e75caced513bf8561e9a03209de9ccf300a8a63523e4963f58b74488af2e7ba',
            'x64' => '1560cb10a2394e3bf24b3eb51b3313fbf6e97305d5dabb60da961133c168bf4a',
            'tar' => '07b47225be858eb7ad09f3b434d4865096ab10df92b0499fb234ef270500caac'
          },
          'software' => {
            'x32' => '0d5df8e9001ee5d6d7d20fa678d762de35ff22f6aaadd6f206927ed286ca5498',
            'x64' => '4e8ed1a8f480a083ad8025e0998795e6613e90cf1e67c7b1e2ab65facf327701',
            'tar' => '20231b9e3e19b9b52a69e31c9921c9b6876624309da59c9689020dfd1f305944'
          }
        },
        '7.3.1' => {
          'core' => {
            'x32' => 'f0e68ae0a8df173ffb2e1899a619d4f6995fafc71c50dc7842d285ade12d2a06',
            'x64' => 'e9eeb67157e0f16e2b31a3d7d8c0618bb394bff90cd037646d1fd7a87dff8e7b',
            'tar' => '21fa728699f427450eeee5df81dafb5fada6615e5b330fccbf083ac1789bf75d'
          },
          'software' => {
            'x32' => '8a277d0db46e751ca5641b30cb24c1f86a5ba2cd4e842f38e5af589a2006c890',
            'x64' => '8d9582e202642402508be71eb633de16af089fb93d25eba8cf9a6c85728a8db5',
            'tar' => '10b3cb25812a49e9db5350d51e53c157e138b26c1947f260cbbc4b39e4ba3b5e'
          }
        },
        '7.3.2' => {
          'core' => {
            'x32' => 'f3c38160a4254ec11b6071d01c5a052e543bcefa26bd17219c86af32bd276817',
            'x64' => '8a65b8e042b17622a6e123d1d92f0507229e35437d94f84da4fa06be926e5dd2',
            'tar' => '0e72bcc86f1b0e3882bfb4095aba2911c39934eb5e41de2b89f54b56bf8325f0'
          },
          'software' => {
            'x32' => '33f9ac3d6050279d60465aa88e946cde67e47c9a6f3ca53502d26a1f77ef4053',
            'x64' => '47c3ed00671bd59a7e4eac84c736dc20572d167c0678a45c980a2147ba4fc8a1',
            'tar' => '590fd3c76373e487b9244e3127276f4c73d0a2df69507662242801ff9d6f46a3'
          }
        },
        '7.3.3' => {
          'core' => {
            'x32' => '91267ca31d94629419c36337df3128db6c1a09370d5474845b7fd624bcb12a94',
            'x64' => '640d693737e178326053d06a7a81ca30340d02ad433ead228885933f200efc6e',
            'tar' => 'b3428cb8e2088c98ddd28632f86588c334c1cb537b98f1be3248b38bc4b9a2d8'
          },
          'software' => {
            'x32' => 'd0eed0f8fff5ffe33a3303420db04f4c575fc6de49272e3aabab3fbc0c1e8bc0',
            'x64' => 'e00c469e73d41977eb92aaeb1af1ca65cb1cd6d08ea4a4843286cf42640bfc57',
            'tar' => '30beb999e42fb6efcd52c06c05465de5b025b5c29fd1860ccf2ab7b3c64111c3'
          }
        },
        '7.3.4' => {
          'core' => {
            'x32' => '12a6d8c0a21544698a0eafa760f9a0ebdac0a23509373b2ef8096f529a78971c',
            'x64' => 'edef74c40fbda862c60b46b929009421761d18dc2f9d036f739874a4200deea6',
            'tar' => 'af5fecffa8da44618bffd9ba68816f7bc4d0ce3a8cac7917c05d41119918c22a'
          },
          'software' => {
            'x32' => '189df4fd058212a9e0ec79b0401876cd2158ac1f6b5c1b94a8a19c51804dc40c',
            'x64' => 'ffb1f10df3f3f21219f854113a273aeb6f724165642af578bbacb5dcd4e870c1',
            'tar' => 'e76d827ded166a0edead6cbed316f9ddbb90999a78b541b3289bc3332c727c76'
          }
        },
        '7.3.5' => {
          'core' => {
            'x32' => 'e3547b3abd75a0b235f1675828d6eba332143011afc5ac2c4532984226d5aaa5',
            'x64' => '40eb2b3af3dd0809dc8d42be4ed26c12356b2caf869eb469fab133383e5e0160',
            'tar' => '7c2cc62000fae8d85950611413266dd12f7acdbb77fe636991e937977e731b1e'
          },
          'software' => {
            'x32' => '7bf262a6d99f3d6e49fdb69d94d13726e44bbc2395a6dc0101ae4ce85649fce4',
            'x64' => 'b7675a8f0044883dd4152f373806ad0d585f4da3ddd7d441947a6d8aeaf0c23b',
            'tar' => 'e974a927efd90c926be32b47e8b456f41c54cd3d92a88bf8fdc8887aa8d28776'
          }
        },
        '7.3.6' => {
          'core' => {
            'x32' => 'c53b029d734cee55e015e47d9b153afaca36d0f0c710f422feee485a1f2edd4a',
            'x64' => '2bd54b26c475367e506aa34a503ba776a89f8e00f40ca51893438695d855e436',
            'tar' => '8685fe2b259eb3760ea43f8105218b11c5ad581707dd6ad7d3a02672ccb78b85'
          },
          'software' => {
            'x32' => '5c290b607858bea53816bc1f00630f0416e24d87fefcf4ae50b89c05b363d686',
            'x64' => '02ee71ca099e8dfafc8a1eb3999efda00227d7f8e18f48aecb15cdac8a10dd33',
            'tar' => 'd9a7b94bd788ca763a638ee5fa9e2e728bc1f1098fb79fffbbc9915d134d7d14'
          }
        },
        '7.3.7' => {
            'core' => {
                'x32' => 'be119c3b34af5578f611bbee4cd83021fd0371f103541e6264d7c63acb86beb5',
                'x64' => '5db66f18d3ebc0f4c87f73c49a0315bb4dfc7aee5c784679f29a0fba483de027',
                'tar' => '1b1a60b814cb003a13b674f280cbe8043f723dcdeaa3312bf86a3d95d795691e',
            },
            'software' => {
                'x32' => 'b3c1bb8222f4e87ece32b854999833f21b0e4d28a85ca07bd314daa1dacc98f9',
                'x64' => '677991c42c24f1f19b61b350c0670348cdeb4137af828b55d1ce692c05bae35e',
                'tar' => '170bc851aefe77c4c783ea8472ebec513de45b659ddf949b4d370ae907b7b6c7',
            }
        },
        '7.3.8' => {
            'core' => {
                'x32' => '11e06ea106e90510847ddd5d3cb0ecb611744b1f3dde3e4a383854458cab6c8b',
                'x64' => '599751fa1a5853d82e2e73e0894f082269b490f6296a7247d3c265f302c76598',
                'tar' => 'f4c3fabeed1e7fbac64a195061e25831d35bc0ab014b5a44d7533a1d3a233878',
            },
            'software' => {
                'x32' => '2c3cfd94917f1619005a592b590848c57b9b2279b70e689edababfbd4f5cb2b6',
                'x64' => '006fca290bd9de1cdc4b0bb281e124068f58129a4cf7ca0501a86bfd4ca16b55',
                'tar' => '0ed7277ec6d9fd45d56b4a30d75b036af70ba7fee3e4e9c585725373aee4fce0',
            }
        },
        '7.4.0' => {
            'core' => {
                'x32' => 'dfe5140d266c157e56f37116968ca1910d93eb584bf4ddfb1bdc61983233ed3a',
                'x64' => '60ec0dbd57a5a2b18b8dc65291b857f81ed3c2d0dcd65ae05a976e7f6f8a86cd',
                'tar' => 'b3a504a8ad184f1dc60bcce04f9ff111355dbfee99df9bea0d49760f1b318a15',
            },
            'software' => {
                'x32' => '99fe7854aeb211b582d35fc6a4bbe43aeb6a2dc426d3af348859a7fe599d93c0',
                'x64' => '15a6fa4e95b0e0272c2338cbb9732f8746928de0775aa49b65d2b7f906f6af10',
                'tar' => '303b9c810ea8354ff8471922e563f22585ba7bc3b3a010f4fa5353a12fbbe18a',
            }
        },
        '7.4.1' => {
            'core' => {
                'x32' => '7cd2507b13299d95464adda163cbbf20362208e584422240dd99c41bf609af1d',
                'x64' => '30921aad18b7747f3da9394d43500ebcaaa1025d3e0fb2cf19a1e1339d796354',
                'tar' => '2e5b0e2e13d60541ee51f2075ec52977e4b03fc6399bfb9081f16652925d8989',
            },
            'software' => {
                'x32' => '4a42a02958885e05f6f9891876d4afdf2595763027c42c2043228d3fe877a659',
                'x64' => '0a9c72d4ab155746cecf3924146a572d9388c735fae30c72b5619622ba95f3de',
                'tar' => '0bbfa213ad7e3e62963ba1098dbb26a2c7da9ff8681b2255bc7f7c030483b3c7',
            }
        },
        '7.4.2' => {
            'core' => {
                'x32' => 'f08703401c89e75f88e23bedefa16d575c90e2c0a79404572284f34fff876a85',
                'x64' => 'fb1a671e475d0972722fe95c5266c98da99021968c19a8349a0b5f11803179b2',
                'tar' => '348f005bc4383ceac68dea93a5caded6eeb77ef65796d2a425fa08b89b84bc0b',
            },
            'software' => {
                'x32' => '8d472cc96d60eb99b08366c4eb20889f4a26ce29514040dd8338779bdcaa2592',
                'x64' => '300fdde3c2a95c0429ff7b3e4697604761b0562cb5ee07e93c17de8c3758e2ba',
                'tar' => '7f8acde6aeecdb75b93ee4253ce69e423e41e1d5205c4ac9525d9735150bb1ef',
            }
        }
      }
    end
    # rubocop:enable Metrics/MethodLength

    # rubocop:disable Metrics/AbcSize
    # Function to truncate value to 4 significant bits, render human readable.
    #
    # The output is a human readable string that ends with "g", "m" or "k" if
    # over 1023. The output may be up to 6.25% less than the original value
    # because of the rounding.
    def binround(value)
      # Keep a multiplier which grows through powers of 1
      multiplier = 1

      # Truncate value to 4 most significant bits
      while value >= 16
        value = (value / 2).floor
        multiplier *= 2
      end

      # Factor any remaining powers of 2 into the multiplier
      while value == 2 * (value / 2).floor
        value = (value / 2).floor
        multiplier *= 2
      end

      # Factor enough powers of 2 back into the value to
      # leave the multiplier as a power of 1024 that can
      # be represented as units of "g", "m" or "k".

      # Disabled g and k calculations for now because we prefer easy comparison between values

      # if multiplier >= 1024 * 1024 * 1024
      #   while multiplier > 1024 * 1024 * 1024
      #     value *= 2
      #     multiplier = (multiplier / 2).floor
      #   end
      #   multiplier = 1
      #   units = 'g'

      # elsif multiplier >= 1024 * 1024
      if multiplier >= 1024 * 1024
        while multiplier > 1024 * 1024
          value *= 2
          multiplier = (multiplier / 2).floor
        end
        multiplier = 1
        units = 'm'

      # elsif multiplier >= 1024
      #   while multiplier > 1024
      #     value *= 2
      #     multiplier = (multiplier / 2).floor
      #   end
      #   multiplier = 1
      #   units = 'k'

      else
        units = ''
      end

      # Now we can return a nice human readable string.
      "#{multiplier * value}#{units}"
    end # end normalize def
    # rubocop:enable Metrics/AbcSize
  end
  # rubocop:enable Metrics/ModuleLength
end

::Chef::Recipe.send(:include, Jira::Helpers)
::Chef::Resource.send(:include, Jira::Helpers)
