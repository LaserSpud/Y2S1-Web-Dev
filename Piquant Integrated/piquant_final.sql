CREATE DATABASE IF NOT EXISTS `Piquant` DEFAULT CHARACTER SET utf8 COLLATE
utf8_general_ci;
USE `Piquant`;

Delimiter $$
create procedure error_handling()
begin
Declare continue handler for 1062
select 'Duplicate keys found';
Declare continue handler for 1064
select 'unknown command'; 

CREATE TABLE IF NOT EXISTS `Menu`(`item_code` varchar(6), item_name varchar(50), item_price decimal(3,2),
                                    PRIMARY KEY(item_code));

CREATE TABLE IF NOT EXISTS `Cart`(`order_num` varchar(17) NOT NULL,
								  `table_num` varchar(6) NOT NULL, `email` varchar(100) NOT NULL, 
                                   `item_code` varchar(6) NOT NULL, `status` varchar(15),
                                   PRIMARY KEY(`order_num`)
                                   );

#CREATE TABLE IF NOT EXISTS `Staff`(`staff_id` varchar(7) NOT NULL, `hire_date` date NOT NULL, `job_title` varchar(60),
                                    #primary key(`staff_id`));

# CREATE TABLE IF NOT EXISTS `Members`(`member_level` integer(3), `member_completion` integer(3));

CREATE TABLE IF NOT EXISTS `Reservation`(`reservation_id` int(6) NOT NULL AUTO_INCREMENT, `full_name` varchar(50),
										 `email` varchar(100) NOT NULL, `phone_num` varchar(8) NOT NULL,
                                           `reservation_date` date NOT NULL, `reservation_time` time NOT NULL,
                                           `card_name` varchar(50), `card_number` varchar(255) NOT NULL, 
                                           `expiry_date` date NOT NULL, `cvv` varchar(255) NOT NULL,
                                           `additional_note` varchar(100), `encrypt_key` varchar(255) NOT NULL,
                                           PRIMARY KEY(`reservation_id`)) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `Account`(`email` varchar(100) NOT NULL, `full_name` varchar(50),
                                        `password` varchar(255) NOT NULL, `pwd_expiry` date, `account_type` varchar(50),
                                        `phone_num` varchar(8) NOT NULL, `member_level` varchar(30), 
                                        `member_completion` varchar(8), `sign_up_date` date,
                                        `staff_id` varchar(30), `manager_id` varchar(30), `hire_date` date, `job_title` varchar(60),
                                        `account_status` varchar(50),  `2fa_status` varchar(3),
                                        PRIMARY KEY(`email`));
                                       
CREATE TABLE IF NOT EXISTS `Rewards`(`reward_code` varchar(10), `status` varchar(20),
                                         PRIMARY KEY(`reward_code`));      

CREATE TABLE IF NOT EXISTS `Password_Hist`(`serial_no` int NOT NULL AUTO_INCREMENT, `email` varchar(100) NOT NULL, 
										    `password` varchar(255) NOT NULL, 
											PRIMARY KEY(`serial_no`)) ENGINE=InnoDB;   
   
CREATE TABLE IF NOT EXISTS `security_qn`(`email`  varchar(100) NOT NULL, `Security_Question` varchar(200) NOT NULL,
										 `answer` varchar(5) NOT NULL,
                                         PRIMARY KEY(`email`));                                         

CREATE TABLE IF NOT EXISTS `Audit`(`email` varchar(100) NOT NULL, `full_name` varchar(50), `staff_id` varchar(30), `manager_id` varchar(30), `login_time` varchar(200), `logout_time` varchar(200),
`action` varchar(100) DEFAULT 'No action', `failed_login` int(100) DEFAULT 0, `usage` int(100), `role` varchar(50), `suspicious` int(100) default 0,
PRIMARY KEY (`email`),
CONSTRAINT FK_AccountEmail FOREIGN KEY (`email`) references piquant.account(`email`));

# staff account
insert into piquant.account VALUES('chanjcjoel@gmail.com', 'Joel Chan', '69',null, 'Staff','98117266', null, null, null, 'Joel', null, '2021-07-01', 'chef',null,null);
insert into piquant.account VALUES('ianwxsim@gmail.com', 'Ian Sim','123',null, 'Staff','91343211', null, null, null, 'Ian', 'Ian', '2021-07-01', 'manager',null,null);
insert into piquant.account VALUES('hozhiyang2003@gmail.com','Ho Zhi Yang','77',null,'Staff','91454233', null, null, null, 'ZY', null, '2021-07-01', 'waiter',null,null);
insert into piquant.account VALUES('destion91@gmail.com', 'Akif Suwandi','5',null,'Staff','97144408', null, null, null, 'Akif', null,'2021-07-01', 'head chef',null,null);
insert into piquant.account VALUES('thisisernestyan@gmail.com', 'Ernest Yan','10',null,'Staff','91266538', null, null, null, 'Ernest','Ernest', '2021-07-01', 'manager',null,null);

# member account
insert into piquant.account VALUES('13458769ey@gmail.com', 'Ernest Yan','redhat','Member','97283234','Regular','1/5','2021-07-05',null,null,null,null);


#user audit

insert into piquant.audit VALUES('thisisernestyan@gmail.com', 'Ernest Yan','Ernest','Ernest',null,null,'No action',0,null,'Manager',0);
insert into piquant.audit VALUES('chanjcjoel@gmail.com', 'Joel Chan', 'Joel',null,null,null,'No action',0,null, 'Staff',0);
insert into piquant.audit VALUES('ianwxsim@gmail.com', 'Ian Sim','Ian','Ian',null,null, 'No action',0,null,'Manager',0);
insert into piquant.audit VALUES('hozhiyang2003@gmail.com','Ho Zhi Yang', 'ZY',null,null,null,'No action',0,null,'Staff',0);
insert into piquant.audit VALUES('destion91@gmail.com', 'Akif Suwandi','Akif',null,null,null,'No action',0,null,'Staff',0);

select * from piquant.audit;

drop table audit;

end $$
Delimiter ;

call error_handling();

create view Staff_Audit as
select * from piquant.audit; 

create user "Ian" identified by "redhat";
create user "Ernest" identified by "handsome";

create role Manager;
grant Manager to Ian, Ernest;
grant all on Staff_Audit to Manager;

select * from audit;

select * from suspicious;