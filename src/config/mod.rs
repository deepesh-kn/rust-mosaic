// Copyright 2018 OpenST Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module handles all configuration of this library.

use std::env;
use std::error::Error;
use std::time::Duration;
use web3::types::{Address, U64, U128, H256};

// Environment variables and their defaults
const ENV_ORIGIN_ENDPOINT: &str = "MOSAIC_ORIGIN_ENDPOINT";
const DEFAULT_ORIGIN_ENDPOINT: &str = "http://127.0.0.1:8545";
const ENV_AUXILIARY_ENDPOINT: &str = "MOSAIC_AUXILIARY_ENDPOINT";
const DEFAULT_AUXILIARY_ENDPOINT: &str = "http://127.0.0.1:8546";
const ENV_ORIGIN_CORE_ADDRESS: &str = "MOSAIC_ORIGIN_CORE_ADDRESS";
const ENV_ORIGIN_VALIDATOR_ADDRESS: &str = "MOSAIC_ORIGIN_VALIDATOR_ADDRESS";
const ENV_AUXILIARY_VALIDATOR_ADDRESS: &str = "MOSAIC_AUXILIARY_VALIDATOR_ADDRESS";
const ENV_ORIGIN_BLOCK_STORE_ADDRESS: &str = "MOSAIC_ORIGIN_BLOCK_STORE_ADDRESS";
const ENV_AUXILIARY_BLOCK_STORE_ADDRESS: &str = "MOSAIC_AUXILIARY_BLOCK_STORE_ADDRESS";
const ENV_ORIGIN_POLLING_INTERVAL: &str = "MOSAIC_ORIGIN_POLLING_INTERVAL";
const DEFAULT_ORIGIN_POLLING_INTERVAL: &str = "1";
const ENV_AUXILIARY_POLLING_INTERVAL: &str = "MOSAIC_AUXILIARY_POLLING_INTERVAL";
const DEFAULT_AUXILIARY_POLLING_INTERVAL: &str = "1";
const ENV_ORIGIN_EPOCH_LENGTH: &str = "MOSAIC_ORIGIN_EPOCH_LENGTH";
const DEFAULT_ORIGIN_EPOCH_LENGTH: &str = "100";
const ENV_AUXILIARY_EPOCH_LENGTH: &str = "MOSAIC_AUXILIARY_EPOCH_LENGTH";
const DEFAULT_AUXILIARY_EPOCH_LENGTH: &str = "100";
const ENV_ORIGIN_INITIAL_BLOCK_HASH: &str = "MOSAIC_ORIGIN_INITIAL_BLOCK_HASH";
const ENV_AUXILIARY_INITIAL_BLOCK_HASH: &str = "MOSAIC_AUXILIARY_INITIAL_BLOCK_HASH";
const ENV_ORIGIN_INITIAL_BLOCK_HEIGHT: &str = "MOSAIC_ORIGIN_INITIAL_BLOCK_HEIGHT";
const ENV_AUXILIARY_INITIAL_BLOCK_HEIGHT: &str = "MOSAIC_AUXILIARY_INITIAL_BLOCK_HEIGHT";

/// Global config for running a mosaic node.
#[derive(Default)]
pub struct Config {
    /// Address of the origin chain, e.g. "127.0.0.1:8485"
    origin_endpoint: String,
    /// Address of the auxiliary chain, e.g. "127.0.0.1:8486"
    auxiliary_endpoint: String,
    /// The address of a core address on origin.
    /// It is optional as it may not be needed depending on the mode that the node is run in.
    _origin_core_address: Option<Address>,
    /// The address that is used to send messages as a validator on origin.
    origin_validator_address: Address,
    /// The address that is used to send messages as a validator on auxiliary.
    auxiliary_validator_address: Address,
    /// The address of origin block store contract.
    origin_block_store_address: Address,
    /// The address of auxiliary block store contract.
    auxiliary_block_store_address: Address,
    origin_polling_interval: Duration,
    auxiliary_polling_interval: Duration,
    /// The casper ffg epoch length for origin.
    origin_epoch_length: U64,
    /// The casper ffg epoch length for auxiliary.
    auxiliary_epoch_length: U64,
    /// The initial block hash for origin.
    origin_initial_block_hash: H256,
    /// The initial block hash for auxiliary.
    auxiliary_initial_block_hash: H256,
    /// The initial block height for origin.
    origin_initial_block_height:U128,
    /// The initial block height for auxiliary.
    auxiliary_initial_block_height:U128,
}

impl Config {
    /// Reads the configuration from environment variables and creates a new Config from them. In
    /// case an environment variable is not set, a default fallback will be used if available.
    ///
    /// # Returns
    ///
    /// Returns a configuration with the settings read from the environment.
    ///
    /// # Panics
    ///
    /// This function panics if a mandatory value cannot be read and there is no default.
    /// This function also panics if a value cannot be parsed into its appropriate type.
    pub fn new() -> Config {
        let origin_endpoint = match Self::read_environment_variable(
            ENV_ORIGIN_ENDPOINT,
            Some(DEFAULT_ORIGIN_ENDPOINT),
        ) {
            Some(origin_endpoint) => origin_endpoint,
            None => panic!("An origin endpoint must be set"),
        };
        let auxiliary_endpoint = match Self::read_environment_variable(
            ENV_AUXILIARY_ENDPOINT,
            Some(DEFAULT_AUXILIARY_ENDPOINT),
        ) {
            Some(auxiliary_endpoint) => auxiliary_endpoint,
            None => panic!("An auxiliary endpoint must be set"),
        };

        let origin_core_address =
            match Self::read_environment_variable(ENV_ORIGIN_CORE_ADDRESS, None) {
                Some(origin_core_address) => Some(
                    origin_core_address
                        .parse::<Address>()
                        .expect("The origin core address cannot be parsed"),
                ),
                None => None,
            };

        let origin_validator_address =
            match Self::read_environment_variable(ENV_ORIGIN_VALIDATOR_ADDRESS, None) {
                Some(origin_validator_address) => origin_validator_address
                    .parse::<Address>()
                    .expect("The origin validator address cannot be parsed"),
                None => panic!("An origin validator address must be set"),
            };

        let auxiliary_validator_address =
            match Self::read_environment_variable(ENV_AUXILIARY_VALIDATOR_ADDRESS, None) {
                Some(auxiliary_validator_address) => auxiliary_validator_address
                    .parse::<Address>()
                    .expect("The auxiliary validator address cannot be parsed"),
                None => panic!("An auxiliary validator address must be set"),
            };

        let origin_block_store_address =
            match Self::read_environment_variable(ENV_ORIGIN_BLOCK_STORE_ADDRESS, None) {
                Some(auxiliary_validator_address) => auxiliary_validator_address
                    .parse::<Address>()
                    .expect("The origin block store address cannot be parsed"),
                None => panic!("An origin block store address must be set"),
            };

        let auxiliary_block_store_address =
            match Self::read_environment_variable(ENV_AUXILIARY_BLOCK_STORE_ADDRESS, None) {
                Some(auxiliary_validator_address) => auxiliary_validator_address
                    .parse::<Address>()
                    .expect("The auxiliary block store address cannot be parsed"),
                None => panic!("An auxiliary block store address must be set"),
            };

        let origin_polling_interval = match Self::read_environment_variable(
            ENV_ORIGIN_POLLING_INTERVAL,
            Some(DEFAULT_ORIGIN_POLLING_INTERVAL),
        ) {
            Some(origin_polling_interval) => match string_to_seconds(&origin_polling_interval) {
                Ok(duration) => duration,
                Err(error) => panic!(
                    "Could not parse given seconds '{}' to origin polling interval: {}",
                    origin_polling_interval, error
                ),
            },
            None => panic!("An origin polling period must be set"),
        };

        let auxiliary_polling_interval = match Self::read_environment_variable(
            ENV_AUXILIARY_POLLING_INTERVAL,
            Some(DEFAULT_AUXILIARY_POLLING_INTERVAL),
        ) {
            Some(auxiliary_polling_interval) => {
                match string_to_seconds(&auxiliary_polling_interval) {
                    Ok(duration) => duration,
                    Err(error) => panic!(
                        "Could not parse given seconds '{}' to origin polling interval: {}",
                        auxiliary_polling_interval, error
                    ),
                }
            }
            None => panic!("An auxiliary polling period must be set"),
        };

        let origin_epoch_length = Self::read_origin_epoch_length();
        let auxiliary_epoch_length = Self::read_auxiliary_epoch_length();
        let origin_initial_block_hash = Self::read_origin_initial_block_hash();
        let auxiliary_initial_block_hash = Self::read_auxiliary_initial_block_hash();
        let origin_initial_block_height = Self::read_origin_initial_block_height();
        let auxiliary_initial_block_height = Self::read_auxiliary_initial_block_height();

        Config {
            origin_endpoint,
            auxiliary_endpoint,
            _origin_core_address: origin_core_address,
            origin_validator_address,
            auxiliary_validator_address,
            origin_block_store_address,
            auxiliary_block_store_address,
            origin_polling_interval,
            auxiliary_polling_interval,
            origin_epoch_length,
            auxiliary_epoch_length,
            origin_initial_block_hash,
            auxiliary_initial_block_hash,
            origin_initial_block_height,
            auxiliary_initial_block_height,
        }
    }

    /// Reads an environment variable for casper ffg epoch length for origin chain and return the
    /// value if found or a default if given.
    ///
    /// # Returns
    ///
    /// A U64 value for origin chain casper ffg epoch length.
    fn read_origin_epoch_length() -> U64 {
        let origin_epoch_length = match Self::read_environment_variable(
            ENV_ORIGIN_EPOCH_LENGTH,
            Some(DEFAULT_ORIGIN_EPOCH_LENGTH),
        ) {
            Some(origin_epoch_length) => origin_epoch_length
                .parse::<U64>()
                .expect("The origin epoch length cannot be parsed"),
            None => panic!("An origin epoch length must be set"),
        };
        origin_epoch_length
    }

    /// Reads an environment variable for casper ffg epoch length for auxiliary chain and return the
    /// value if found or a default if given.
    ///
    /// # Returns
    ///
    /// A U64 value for auxiliary chain casper ffg epoch length.
    fn read_auxiliary_epoch_length() -> U64 {
        let auxiliary_epoch_length = match Self::read_environment_variable(
            ENV_AUXILIARY_EPOCH_LENGTH,
            Some(DEFAULT_AUXILIARY_EPOCH_LENGTH),
        ) {
            Some(auxiliary_epoch_length) => auxiliary_epoch_length
                .parse::<U64>()
                .expect("The auxiliary epoch length cannot be parsed"),
            None => panic!("An auxiliary epoch length must be set"),
        };
        auxiliary_epoch_length
    }

    /// Reads an environment variable for initial block hash for origin chain and return the
    /// value if found or a default if given.
    ///
    /// # Returns
    ///
    /// A H256 value for initial block hash of origin chain.
    fn read_origin_initial_block_hash() -> H256 {
        let origin_initial_block_hash =
            match Self::read_environment_variable(
                ENV_ORIGIN_INITIAL_BLOCK_HASH,
                None
            ) {
            Some(origin_initial_block_hash) => origin_initial_block_hash
                .parse::<H256>()
                .expect("The origin initial block hash cannot be parsed"),
            None => panic!("An origin initial block hash must be set"),
        };
        origin_initial_block_hash
    }

    /// Reads an environment variable for initial block hash for auxiliary chain and return the
    /// value if found or a default if given.
    ///
    /// # Returns
    ///
    /// A H256 value for initial block hash of auxiliary chain.
    fn read_auxiliary_initial_block_hash() -> H256 {
        let auxiliary_initial_block_hash =
            match Self::read_environment_variable(
                ENV_AUXILIARY_INITIAL_BLOCK_HASH,
                None
            ) {
                Some(auxiliary_initial_block_hash) => auxiliary_initial_block_hash
                    .parse::<H256>()
                    .expect("The auxiliary initial block hash cannot be parsed"),
                None => panic!("An auxiliary initial block hash must be set"),
            };
        auxiliary_initial_block_hash
    }

    /// Reads an environment variable for initial block height for origin chain and return the
    /// value if found or a default if given.
    ///
    /// # Returns
    ///
    /// A U128 value for initial block height of origin chain.
    fn read_origin_initial_block_height() -> U128 {
        let origin_initial_block_height =
            match Self::read_environment_variable(
                ENV_ORIGIN_INITIAL_BLOCK_HEIGHT,
                None
            ) {
                Some(origin_initial_block_height) => origin_initial_block_height
                    .parse::<U128>()
                    .expect("The origin initial block height cannot be parsed"),
                None => panic!("An origin initial block height must be set"),
            };
        origin_initial_block_height
    }

    /// Reads an environment variable for initial block height for auxiliary chain and return the
    /// value if found or a default if given.
    ///
    /// # Returns
    ///
    /// A U128 value for initial block height of auxiliary chain.
    fn read_auxiliary_initial_block_height() -> U128 {
        let auxiliary_initial_block_height =
            match Self::read_environment_variable(
                ENV_AUXILIARY_INITIAL_BLOCK_HEIGHT,
                None
            ) {
                Some(auxiliary_initial_block_height) => auxiliary_initial_block_height
                    .parse::<U128>()
                    .expect("The auxiliary initial block height cannot be parsed"),
                None => panic!("An auxiliary initial block height must be set"),
            };
        auxiliary_initial_block_height
    }

    /// Reads an environment variable and return the value if found or a default if given.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the environment variable.
    /// * `default_value` - An optional default value if the environment variable is not set.
    ///
    /// # Returns
    ///
    /// An optional string that is the value of the environment variable if set or the default if
    /// given.
    fn read_environment_variable(name: &str, default_value: Option<&str>) -> Option<String> {
        let value = match env::var(name) {
            Ok(value) => Some(value),
            Err(_) => match default_value {
                Some(default_value) => {
                    info!("No {} found, falling back to default.", name);
                    Some(default_value.to_owned())
                }
                None => None,
            },
        };

        info!(
            "Using {}: {}",
            name,
            match &value {
                Some(value) => value,
                None => "<not set>",
            }
        );

        value
    }

    /// Returns the origin endpoint set on this config.
    pub fn origin_endpoint(&self) -> &String {
        &self.origin_endpoint
    }

    /// Returns the auxiliary endpoint set on this config.
    pub fn auxiliary_endpoint(&self) -> &String {
        &self.auxiliary_endpoint
    }

    /// Returns the origin validator address set on this config.
    pub fn origin_validator_address(&self) -> Address {
        self.origin_validator_address
    }

    /// Returns the auxiliary validator address set on this config.
    pub fn auxiliary_validator_address(&self) -> Address {
        self.auxiliary_validator_address
    }

    /// Returns the address of origin block store.
    pub fn origin_block_store_address(&self) -> Address {
        self.origin_block_store_address
    }

    /// Returns the address of auxiliary block store.
    pub fn auxiliary_block_store_address(&self) -> Address {
        self.auxiliary_block_store_address
    }

    pub fn origin_polling_interval(&self) -> Duration {
        self.origin_polling_interval
    }

    pub fn auxiliary_polling_interval(&self) -> Duration {
        self.auxiliary_polling_interval
    }

    /// Returns the origin chain casper ffg epoch length.
    pub fn origin_epoch_length(&self) -> U64 {
        self.origin_epoch_length
    }

    /// Returns the auxiliary chain casper ffg epoch length.
    pub fn auxiliary_epoch_length(&self) -> U64 {
        self.auxiliary_epoch_length
    }

    /// Returns the origin chain initial block hash.
    pub fn origin_initial_block_hash(&self) -> H256 {
        self.origin_initial_block_hash
    }

    /// Returns the auxiliary chain initial block hash.
    pub fn auxiliary_initial_block_hash(&self) -> H256 {
        self.auxiliary_initial_block_hash
    }

    /// Returns the origin chain initial block height.
    pub fn origin_initial_block_height(&self) -> U128 {
        self.origin_initial_block_height
    }

    /// Returns the auxiliary chain initial block height.
    pub fn auxiliary_initial_block_height(&self) -> U128 {
        self.auxiliary_initial_block_height
    }
}

/// Parses a string of numbers into a duration in seconds.
/// For example, if the string is "15", then the function will return a duration that represents 15
/// seconds.
///
/// # Arguments
///
/// * `string` - A string that holds a number, e.g. "15".
fn string_to_seconds(string: &str) -> Result<Duration, Box<Error>> {
    let seconds = try!(string.parse::<u64>());

    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn the_config_reads_the_environment_variables() {
        // Testing that the config falls back to the default values.

        // These must be set without a fallback. Mandatory.
        env::set_var(
            ENV_ORIGIN_VALIDATOR_ADDRESS,
            "6789012345678901234567890123456789012345",
        );
        env::set_var(
            ENV_AUXILIARY_VALIDATOR_ADDRESS,
            "1234567890123456789012345678901234567890",
        );
        env::set_var(
            ENV_ORIGIN_BLOCK_STORE_ADDRESS,
            "5678901234123456789012345678901234567890",
        );
        env::set_var(
            ENV_AUXILIARY_BLOCK_STORE_ADDRESS,
            "5678901234123456789012345678901234567890",
        );
        env::set_var(
            ENV_ORIGIN_INITIAL_BLOCK_HASH,
            "b6a85955e3671040901a17db85b121550338ad1a0071ca13d196d19df31f56ca",
        );
        env::set_var(
            ENV_AUXILIARY_INITIAL_BLOCK_HASH,
            "5fe50b260da6308036625b850b5d6ced6d0a9f814c0688bc91ffb7b7a3a54b67",
        );
        env::set_var(
            ENV_ORIGIN_INITIAL_BLOCK_HEIGHT,
            "100",
        );
        env::set_var(
            ENV_AUXILIARY_INITIAL_BLOCK_HEIGHT,
            "100",
        );


        let config = Config::new();
        assert_eq!(
            config.origin_endpoint,
            DEFAULT_ORIGIN_ENDPOINT.to_owned(),
            "Did not set the default origin endpoint when no ENV var set.",
        );
        assert_eq!(
            config.auxiliary_endpoint,
            DEFAULT_AUXILIARY_ENDPOINT.to_owned(),
            "Did not set the default auxiliary endpoint when no ENV var set.",
        );

        // Testing that set values are read.
        // Testing both cases in one test method so that there is no race condition between setting
        // and removing env variables, as rust runs test methods in parallel.

        let expected_origin_endpoint = "10.0.0.1";
        env::set_var(ENV_ORIGIN_ENDPOINT, expected_origin_endpoint);

        let config = Config::new();
        assert_eq!(
            config.origin_endpoint, expected_origin_endpoint,
            "Did not read the origin endpoint {}, but {} instead",
            expected_origin_endpoint, config.origin_endpoint,
        );
        assert_eq!(
            config.origin_validator_address(),
            "6789012345678901234567890123456789012345"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            config.auxiliary_validator_address(),
            "1234567890123456789012345678901234567890"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            config.origin_block_store_address(),
            "5678901234123456789012345678901234567890"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            config.auxiliary_block_store_address(),
            "5678901234123456789012345678901234567890"
                .parse::<Address>()
                .unwrap()
        );

        env::set_var(ENV_ORIGIN_ENDPOINT, "10.0.0.1");
        let config = Config::new();
        assert_eq!(config.origin_endpoint, "10.0.0.1");
        // Assert also that it does not overwrite the wrong configuration value.
        assert_eq!(
            config.auxiliary_endpoint,
            DEFAULT_AUXILIARY_ENDPOINT.to_owned()
        );

        let expected_auxiliary_endpoint = "10.0.0.2";
        env::set_var(ENV_AUXILIARY_ENDPOINT, expected_auxiliary_endpoint);
        let config = Config::new();
        assert_eq!(
            config.origin_endpoint, expected_origin_endpoint,
            "Did not read the origin endpoint {}, but {} instead",
            expected_origin_endpoint, config.origin_endpoint,
        );
        assert_eq!(
            config.auxiliary_endpoint, expected_auxiliary_endpoint,
            "Did not read the auxiliary endpoint {}, but {} instead",
            expected_auxiliary_endpoint, config.auxiliary_endpoint,
        );

        let env_origin_epoch_length = "1001";
        let env_auxiliary_epoch_length = "2001";
        let env_origin_initial_block_hash =
            "b6a85955e3671040901a17db85b121550338ad1a0071ca13d196d19df31f56ca";
        let env_auxiliary_initial_block_hash =
            "5fe50b260da6308036625b850b5d6ced6d0a9f814c0688bc91ffb7b7a3a54b67";
        let env_origin_initial_block_height = "19001";
        let env_auxiliary_initial_block_height = "45001";

        env::set_var(
            ENV_ORIGIN_EPOCH_LENGTH,
            env_origin_epoch_length,
        );
        env::set_var(
            ENV_AUXILIARY_EPOCH_LENGTH,
            env_auxiliary_epoch_length,
        );
        env::set_var(
            ENV_ORIGIN_INITIAL_BLOCK_HASH,
            env_origin_initial_block_hash,
        );
        env::set_var(
            ENV_AUXILIARY_INITIAL_BLOCK_HASH,
            env_auxiliary_initial_block_hash,
        );
        env::set_var(
            ENV_ORIGIN_INITIAL_BLOCK_HEIGHT,
            env_origin_initial_block_height,
        );
        env::set_var(
            ENV_AUXILIARY_INITIAL_BLOCK_HEIGHT,
            env_auxiliary_initial_block_height,
        );

        let config = Config::new();

        let expected_origin_epoch_length:U64 = env_origin_epoch_length.into();
        let expected_auxiliary_epoch_length:U64 = env_auxiliary_epoch_length.into();
        let expected_origin_initial_block_hash:H256 = env_origin_initial_block_hash.into();
        let expected_auxiliary_initial_block_hash:H256 = env_auxiliary_initial_block_hash.into();
        let expected_origin_initial_block_height:U128 = env_origin_initial_block_height.into();
        let expected_auxiliary_initial_block_height:U128 = env_auxiliary_initial_block_height.into();

        assert_eq!(
            config.origin_epoch_length, expected_origin_epoch_length,
            "Did not read the origin epoch length {}, but {} instead",
            expected_origin_epoch_length, config.origin_epoch_length,
        );
        assert_eq!(
            config.auxiliary_epoch_length, expected_auxiliary_epoch_length,
            "Did not read the auxiliary epoch length {}, but {} instead",
            expected_auxiliary_epoch_length, config.auxiliary_epoch_length,
        );
        assert_eq!(
            config.origin_initial_block_hash, expected_origin_initial_block_hash,
            "Did not read the origin initial block hash {}, but {} instead",
            expected_origin_initial_block_hash, config.origin_initial_block_hash,
        );
        assert_eq!(
            config.auxiliary_initial_block_hash, expected_auxiliary_initial_block_hash,
            "Did not read the auxiliary initial block hash {}, but {} instead",
            expected_auxiliary_initial_block_hash, config.auxiliary_initial_block_hash,
        );
        assert_eq!(
            config.origin_initial_block_height, expected_origin_initial_block_height,
            "Did not read the origin initial block height {}, but {} instead",
            expected_origin_initial_block_height, config.origin_initial_block_height,
        );
        assert_eq!(
            config.auxiliary_initial_block_height, expected_auxiliary_initial_block_height,
            "Did not read the auxiliary initial block height {}, but {} instead",
            expected_auxiliary_initial_block_height, config.auxiliary_initial_block_height,
        );

        env::remove_var(ENV_ORIGIN_ENDPOINT);
        env::remove_var(ENV_AUXILIARY_ENDPOINT);
        env::remove_var(ENV_ORIGIN_VALIDATOR_ADDRESS);
        env::remove_var(ENV_AUXILIARY_VALIDATOR_ADDRESS);
        env::remove_var(ENV_ORIGIN_BLOCK_STORE_ADDRESS);
        env::remove_var(ENV_AUXILIARY_BLOCK_STORE_ADDRESS);
        env::remove_var(ENV_ORIGIN_EPOCH_LENGTH);
        env::remove_var(ENV_AUXILIARY_EPOCH_LENGTH);
        env::remove_var(ENV_ORIGIN_INITIAL_BLOCK_HASH);
        env::remove_var(ENV_AUXILIARY_INITIAL_BLOCK_HASH);
        env::remove_var(ENV_ORIGIN_INITIAL_BLOCK_HEIGHT);
        env::remove_var(ENV_AUXILIARY_INITIAL_BLOCK_HEIGHT);

    }
}
