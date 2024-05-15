--
-- Database: `testing`
--

-- --------------------------------------------------------

--
-- Table structure for table `user_login`
--
USE users;

CREATE TABLE `user_login` (
  `user_id` int(11) NOT NULL,
  `user_name` varchar(100) NOT NULL UNIQUE,
  `user_password` varchar(100) NOT NULL,
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `user_login`
--

INSERT INTO `user_login` (`user_id`, `user_password`, `user_session_id`) VALUES
(1, 'jazmin', 'password', ''),

--
-- Indexes for dumped tables
--

--
-- Indexes for table `user_login`
--
ALTER TABLE `user_login`
  ADD PRIMARY KEY (`user_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `user_login`
--
ALTER TABLE `user_login`
  MODIFY `user_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;


